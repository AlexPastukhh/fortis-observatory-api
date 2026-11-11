"""Isolated HTTP characterization of recovered Observatory source.

Requires Linux/POSIX and exact five-file baseline. Binds ONLY 127.0.0.1 on an
OS-chosen ephemeral port in this test sandbox; no connection to Fortis services.
All mutations are inside tempfile.TemporaryDirectory().
"""
import concurrent.futures
import hashlib
import http.client
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest

from _helpers import verify_source


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'geteuid'),
                     'Linux/POSIX permissions required')
class HTTPSyntheticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = verify_source()
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(source))
        try:
            cls.api = importlib.import_module('gateway')
        finally:
            sys.path.remove(str(source))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ownapi01-http-synthetic-')
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.archive = root / 'archive'
        self.pending = root / 'pending'
        self.receipts = root / 'receipts'
        self.clients = root / 'clients.json'
        for p in (self.archive, self.pending, self.pending / 'event',
                  self.pending / 'message', self.receipts):
            p.mkdir(parents=True, exist_ok=True)
            p.chmod(0o700)
        self.chat = 'synthetic-chat-123'
        self.token = 'A' * 48  # synthetic, never a real credential
        cfg = {
            'version': 1,
            'clients': [{
                'id': 'synthetic-client',
                'token_sha256': hashlib.sha256(self.token.encode('ascii')).hexdigest(),
                'permissions': ['read:metadata', 'read:history', 'write:events', 'write:messages'],
                'chats': [self.chat],
            }],
        }
        self.clients.write_text(json.dumps(cfg), encoding='utf-8')
        self.clients.chmod(0o600)
        self.gw = self.api.Gateway(self.archive, self.pending, self.receipts, self.clients)
        self.server = self.api.ThreadingHTTPServer(
            ('127.0.0.1', 0), self.api.handler_for(self.gw))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.shutdown)
        self.port = self.server.server_address[1]

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def exchange(self, method, path, *, bearer=True, headers=None, body=None):
        hdr = dict(headers or {})
        if bearer:
            hdr.setdefault('Authorization', 'Bearer ' + self.token)
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        try:
            conn.request(method, path, body=body, headers=hdr)
            r = conn.getresponse()
            raw = r.read()
            return r.status, json.loads(raw.decode('utf-8'))
        finally:
            conn.close()

    def msg(self, request_id=None, body='Synthetic message'):
        return {
            'request_id': request_id or ('req_' + 'a' * 32),
            'chat_id': self.chat,
            'task_id': 'task_' + 'b' * 32,
            'kind': 'final',
            'body': body,
        }

    def post(self, payload, *, path='/v1/messages'):
        return self.exchange(
            'POST', path,
            headers={'Content-Type': 'application/json'},
            body=json.dumps(payload),
        )

    def test_health_requires_authentication(self):
        status, payload = self.exchange('GET', '/v1/health', bearer=False)
        self.assertEqual(status, 401)
        self.assertFalse(payload['ok'])

    def test_health_rejects_invalid_bearer(self):
        status, payload = self.exchange('GET', '/v1/health', headers={
            'Authorization': 'Bearer ' + 'B' * 48,
        })
        self.assertEqual(status, 401)

    def test_health_authorized_and_staging_only(self):
        status, payload = self.exchange('GET', '/v1/health')
        self.assertEqual(status, 200)
        self.assertEqual(payload['mode'], 'staging_only')

    def test_disallowed_host_rejected(self):
        status, payload = self.exchange('GET', '/v1/health', headers={
            'Host': 'untrusted.invalid:18756',
        })
        self.assertEqual(status, 403)
        self.assertEqual(payload['error'], 'request_origin_refused')

    def test_browser_origin_rejected(self):
        status, payload = self.exchange('GET', '/v1/health', headers={
            'Origin': 'https://untrusted.invalid',
        })
        self.assertEqual(status, 403)

    def test_fetch_site_rejected(self):
        status, payload = self.exchange('GET', '/v1/health', headers={
            'Sec-Fetch-Site': 'same-origin',
        })
        self.assertEqual(status, 403)

    def test_sessions_without_permission_rejected(self):
        # Mutate only the in-memory synthetic client under test.
        self.gw.clients[0]['permissions'] = frozenset({'write:messages'})
        status, payload = self.exchange('GET', '/v1/sessions')
        self.assertEqual(status, 403)
        self.assertEqual(payload['error'], 'permission_refused')

    def test_sessions_empty_authorized(self):
        status, payload = self.exchange('GET', '/v1/sessions')
        self.assertEqual(status, 200)
        self.assertEqual(payload['sessions'], [])

    def test_post_message_and_receipt(self):
        status, payload = self.post(self.msg())
        self.assertEqual(status, 202)
        self.assertEqual(payload['state'], 'staged_only')
        self.assertTrue(payload['created'])
        self.assertEqual(len(list((self.pending / 'message').glob('*.json'))), 1)
        self.assertEqual(len(list(self.receipts.glob('*.json'))), 1)
        status2, lookup = self.exchange('GET', '/v1/requests/' + self.msg()['request_id'])
        self.assertEqual(status2, 200)
        self.assertEqual(lookup['state'], 'staged_only')

    def test_post_idempotent_replay(self):
        first = self.post(self.msg())
        second = self.post(self.msg())
        self.assertEqual(first[0], 202)
        self.assertEqual(second[0], 200)
        self.assertFalse(second[1]['created'])
        self.assertEqual(len(list((self.pending / 'message').glob('*.json'))), 1)

    def test_post_conflicting_replay(self):
        self.assertEqual(self.post(self.msg())[0], 202)
        status, payload = self.post(self.msg(body='Different synthetic content'))
        self.assertEqual(status, 409)
        self.assertEqual(payload['error'], 'idempotency_conflict')
        self.assertEqual(len(list((self.pending / 'message').glob('*.json'))), 1)

    def test_post_other_chat_rejected_without_write(self):
        request = self.msg()
        request['chat_id'] = 'different-chat-999'
        status, payload = self.post(request)
        self.assertEqual(status, 403)
        self.assertFalse(list((self.pending / 'message').glob('*.json')))

    def test_post_invalid_json_rejected(self):
        status, payload = self.exchange('POST', '/v1/messages',
            headers={'Content-Type': 'application/json'}, body='{bad json')
        self.assertEqual(status, 400)

    def test_duplicate_json_field_rejected(self):
        raw = json.dumps(self.msg())
        raw = raw.replace('"kind": "final"', '"kind": "final", "kind": "interim"')
        self.assertIn('"kind": "interim"', raw)
        status, payload = self.exchange('POST', '/v1/messages',
            headers={'Content-Type': 'application/json'}, body=raw)
        self.assertEqual(status, 400)
        self.assertFalse(list((self.pending / 'message').glob('*.json')))

    def test_invalid_content_type_rejected(self):
        status, payload = self.exchange('POST', '/v1/messages',
            headers={'Content-Type': 'text/plain'}, body=json.dumps(self.msg()))
        self.assertEqual(status, 400)

    def test_oversized_request_rejected_before_read(self):
        status, payload = self.exchange('POST', '/v1/messages',
            headers={'Content-Type': 'application/json',
                     'Content-Length': str(self.api.MAX_BODY + 1)},
            body='x')
        self.assertEqual(status, 400)
        self.assertFalse(list((self.pending / 'message').glob('*.json')))

    def test_put_disallowed(self):
        status, payload = self.exchange('PUT', '/v1/messages')
        self.assertEqual(status, 405)

    def test_unknown_get_route(self):
        status, payload = self.exchange('GET', '/v1/missing')
        self.assertEqual(status, 404)

    def test_post_event_staged(self):
        req = {'request_id': 'req_' + 'c' * 32, 'chat_id': self.chat,
               'task_id': 'task_' + 'd' * 32,
               'sequence': 0, 'event': 'progress', 'stage': 'testing',
               'summary': 'Synthetic progress', 'detail': None}
        status, payload = self.post(req, path='/v1/events')
        self.assertEqual(status, 202)
        self.assertEqual(len(list((self.pending / 'event').glob('*.json'))), 1)

    def test_simultaneous_same_request_no_duplicate_in_normal_path(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.post, self.msg()) for _ in range(2)]
            results = [future.result(timeout=5) for future in futures]
        self.assertEqual(sorted(status for status, payload in results), [200, 202])
        self.assertEqual(len(list((self.pending / 'message').glob('*.json'))), 1)
        self.assertEqual(len(list(self.receipts.glob('*.json'))), 1)


if __name__ == '__main__':
    unittest.main()
