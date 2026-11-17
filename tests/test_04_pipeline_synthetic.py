"""Additional OWNAPI-01 characterization tests. POSIX only, synthetic data only.

Supply OWNAPI_SOURCE_DIR with verified copies of the five recovered files.
These tests never use Docker, real tokens, production volumes, or /data.
"""
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

EXPECTED = {
    'gateway.py': '9a1627decc3a989461b57ae9b5f7a75b93417d65f5e08fe7ca195e4d3ee5f04a',
    'provision.py': '4a020eba83027b3ac09618c17cb13ea08923ead869b1de3f8893cd9b128716b3',
    'store.py': 'd494a44f94b92c294f60277d08f1bf6f5116781a65aa9d24f8c8f8dd5579256b',
    'repo_messages.py': '9258d1adb8e61a613c08ab8be1ef75029321288332e089ba76cde7779222fbbe',
    'repo_pending.py': 'feec7fe2189da1fb7dd9d5ea161220902b4773c60511d102cdbef4d4a519fa09',
}

@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'geteuid'), 'POSIX required')
class SyntheticPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(os.environ['OWNAPI_SOURCE_DIR']).resolve(strict=True)
        for name, digest in EXPECTED.items():
            path = root / name
            if not path.is_file() or path.is_symlink():
                raise RuntimeError('Missing or linked source ' + name)
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise RuntimeError('SHA-256 mismatch ' + name)
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(root))
        try:
            cls.gateway_mod = importlib.import_module('gateway')
            cls.pending_mod = importlib.import_module('repo_pending')
            cls.messages_mod = importlib.import_module('repo_messages')
            cls.store_mod = importlib.import_module('store')
        finally:
            sys.path.remove(str(root))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ownapi01-pipeline-synthetic-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / 'archive'
        self.pending = self.root / 'inbox' / 'pending-context'
        self.event_inbox = self.root / 'inbox' / 'repo'
        self.message_inbox = self.root / 'inbox' / 'messages'
        self.quarantine = self.root / 'quarantine'
        self.receipts = self.root / 'receipts'
        for p in (self.archive, self.pending, self.pending/'event', self.pending/'message',
                  self.event_inbox, self.message_inbox, self.quarantine, self.receipts):
            p.mkdir(parents=True, exist_ok=True)
            p.chmod(0o700)
        self.chat = 'synthetic-chat-01'
        self.token = 'Z' * 48
        self.cfg = self.root / 'clients.json'
        self.cfg.write_text(json.dumps({'version':1,'clients':[{
            'id':'synthetic-client', 'token_sha256':hashlib.sha256(self.token.encode()).hexdigest(),
            'permissions':['read:metadata','read:history','write:events','write:messages'],
            'chats':[self.chat]}]}), encoding='utf-8')
        self.cfg.chmod(0o600)
        self.gateway = self.gateway_mod.Gateway(self.archive, self.pending, self.receipts, self.cfg)
        self.client = self.gateway.authenticate('Bearer ' + self.token)
        self.store = self.store_mod.Store(self.archive, {'repo':self.event_inbox})
        self.message_collector = self.messages_mod.RepoMessages(self.store, self.message_inbox, self.quarantine)

    def register(self):
        return self.store.register('https://chatgpt.com/c/' + self.chat, 'repo', 'Synthetic test session')

    def msg(self):
        return {'request_id':'req_' + '1'*32, 'chat_id':self.chat,
                'task_id':'task_'+'2'*32, 'kind':'final', 'body':'Synthetic message'}

    def event(self):
        return {'request_id':'req_'+'3'*32,'chat_id':self.chat,
                'task_id':'task_'+'4'*32, 'event':'progress','stage':'testing',
                'summary':'Synthetic progress','sequence':0,'detail':None}

    def assert_crash_creates_two_files_one_logical_id(self, kind, req):
        original_atomic = self.gateway_mod._atomic
        def injected(path, payload):
            if Path(path).parent == self.receipts:
                raise OSError('synthetic fault before receipt')
            return original_atomic(path, payload)
        with patch.object(self.gateway_mod, '_atomic', side_effect=injected):
            with self.assertRaises(OSError):
                self.gateway.stage(self.client,kind,req)
        self.gateway.stage(self.client,kind,req)
        staged = list((self.pending/kind).glob('*.json'))
        self.assertEqual(len(staged), 2)
        self.assertEqual(len({json.loads(p.read_text())['record_id'] for p in staged}), 1)

    def test_message_staged_then_forwarded_and_archived(self):
        reg = self.register()
        receipt, created = self.gateway.stage(self.client, 'message', self.msg())
        self.assertTrue(created)
        self.assertEqual(receipt['state'],'staged_only')
        self.assertFalse(list(self.message_inbox.glob('*.json')))
        self.assertEqual(self.pending_mod.poll_pending(self.root, self.store)['staged'], 1)
        self.assertEqual(self.message_collector.poll()['accepted'], 1)
        history = self.gateway.history(self.client, reg['reporting_session_id'], self.msg()['task_id'])
        self.assertEqual([m['body'] for m in history['assistant_messages']], ['Synthetic message'])

    def test_event_staged_then_forwarded_and_archived(self):
        reg = self.register()
        receipt, created = self.gateway.stage(self.client, 'event', self.event())
        self.assertTrue(created)
        self.assertEqual(receipt['state'],'staged_only')
        self.assertEqual(self.pending_mod.poll_pending(self.root, self.store)['staged'], 1)
        self.assertEqual(self.store.poll()['accepted'], 1)
        history = self.gateway.history(self.client, reg['reporting_session_id'], self.event()['task_id'])
        self.assertEqual([e['event'] for e in history['events']], ['progress'])

    def test_message_crash_replay_downstream_deduplicates(self):
        reg = self.register()
        self.assert_crash_creates_two_files_one_logical_id('message', self.msg())
        self.assertEqual(self.pending_mod.poll_pending(self.root,self.store)['staged'], 2)
        downstream = self.message_collector.poll()
        self.assertEqual(downstream['accepted'], 1)
        self.assertEqual(downstream['duplicate'], 1)
        history = self.gateway.history(self.client, reg['reporting_session_id'],self.msg()['task_id'])
        self.assertEqual(len(history['assistant_messages']),1)

    def test_event_crash_replay_downstream_deduplicates(self):
        reg = self.register()
        self.assert_crash_creates_two_files_one_logical_id('event', self.event())
        self.assertEqual(self.pending_mod.poll_pending(self.root,self.store)['staged'], 2)
        downstream = self.store.poll()
        self.assertEqual(downstream['accepted'],1)
        self.assertEqual(downstream['duplicate'],1)
        history = self.gateway.history(self.client,reg['reporting_session_id'],self.event()['task_id'])
        self.assertEqual(len(history['events']),1)

    def test_unregistered_chat_waits_until_registration(self):
        self.gateway.stage(self.client,'message',self.msg())
        first = self.pending_mod.poll_pending(self.root,self.store)
        self.assertEqual(first['waiting_context'],1)
        self.assertEqual(first['staged'],0)
        self.assertEqual(len(list((self.pending/'message').glob('*.json'))),1)
        reg = self.register()
        second = self.pending_mod.poll_pending(self.root,self.store)
        self.assertEqual(second['staged'],1)
        self.assertEqual(self.message_collector.poll()['accepted'],1)
        history=self.gateway.history(self.client,reg['reporting_session_id'],self.msg()['task_id'])
        self.assertEqual(len(history['assistant_messages']),1)

if __name__ == '__main__':
    unittest.main(verbosity=2)
