"""Offline direct-TLS characterization of OWNAPI-GW-01 source candidate.

Synthetic TLS, Bearer and archive only; localhost ephemeral socket; no Docker,
production network, credentials or volumes. TLS fixtures come from ephemeral
CI-runner generation (no openssl binary needed in the pinned Python image);
local runs may generate the same synthetic certificate with OpenSSL.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

from _helpers import verify_source


class LoopbackHTTPS(http.client.HTTPSConnection):
    def connect(self):
        raw = socket.create_connection(('127.0.0.1', self.port), timeout=3)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


@unittest.skipUnless(os.name == 'posix', 'POSIX required')
class HTTPSOnlyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = verify_source()
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(root))
        try:
            import gateway
            cls.api = gateway
        finally:
            sys.path.remove(str(root))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ownapi-gw-https-synthetic-')
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.reader_token = 'R' * 48
        self.writer_token = 'W' * 48
        self.chat = 'synthetic-chat-123'
        for d in ('archive','pending','pending/event','pending/message','receipts'):
            folder = root / d
            folder.mkdir(parents=True, exist_ok=True)
            folder.chmod(0o700)
        self.pending = root / 'pending'
        self.receipts = root / 'receipts'
        clients = root / 'clients.json'
        def client(name, token, permissions):
            return {'id': name, 'token_sha256': hashlib.sha256(token.encode()).hexdigest(),
                    'permissions': permissions, 'chats': [self.chat]}
        clients.write_text(json.dumps({'version': 1, 'clients': [
            client('synreader',self.reader_token,['read:metadata']),
            client('synwriter',self.writer_token,
                   ['read:metadata','read:history','write:messages','write:events'])
        ]}), encoding='utf-8')
        clients.chmod(0o600)
        self.api_gateway = self.api.Gateway(root/'archive',self.pending,
                                            self.receipts,clients)
        self.cert = root/'cert.pem'
        self.key = root/'key.pem'
        fixture_cert = os.environ.get('OWNAPI_TEST_TLS_CERT')
        fixture_key = os.environ.get('OWNAPI_TEST_TLS_KEY')
        if bool(fixture_cert) != bool(fixture_key):
            self.fail('synthetic TLS fixture must provide both cert and key')
        if fixture_cert:
            # CI runner generated these keys outside Git; the bind mount is
            # read-only and the private key never enters the source/image.
            for source, target in ((fixture_cert, self.cert),
                                   (fixture_key, self.key)):
                source = Path(source)
                if not source.is_file() or source.is_symlink():
                    self.fail('synthetic TLS fixture must be a regular file')
                shutil.copyfile(source, target)
        else:
            if not shutil.which('openssl'):
                self.fail('synthetic TLS fixture required when openssl absent')
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                            '-days','1','-subj','/CN=fortis-observatory-api',
                            '-addext','subjectAltName=DNS:fortis-observatory-api',
                            '-out',str(self.cert),'-keyout',str(self.key)],
                           check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        self.cert.chmod(0o644)
        self.key.chmod(0o600)
        self.server = self.api.https_server(
            self.api_gateway,'127.0.0.1',0,self.cert,self.key)
        self.addCleanup(self.close)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.pinned = ssl.create_default_context(cafile=str(self.cert))

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
    def exchange(self, method='GET', path='/v1/health', *, token='reader',
                 host='fortis-observatory-api', dns='fortis-observatory-api',
                 ca=None, body=None, extra=None):
        tls = LoopbackHTTPS(dns,self.port,timeout=3,context=ca or self.pinned)
        headers = {'Host':host}
        if token is not None:
            headers['Authorization'] = 'Bearer ' + (
                self.reader_token if token=='reader' else self.writer_token)
        headers.update(extra or {})
        try:
            tls.request(method,path,body=body,headers=headers)
            answer=tls.getresponse()
            return answer.status,json.loads(answer.read())
        finally:
            tls.close()

    def test_https_health_bare_host_and_explicit_443(self):
        for host in ('fortis-observatory-api','fortis-observatory-api:443'):
            with self.subTest(host=host):
                code,payload=self.exchange(host=host)
                self.assertEqual(code,200)
                self.assertEqual(payload['mode'],'staging_only')

    def test_health_without_bearer_fails_closed(self):
        code,payload=self.exchange(token=None)
        self.assertEqual(code,401)
        self.assertFalse(payload['ok'])

    def test_scoped_sessions(self):
        code,payload=self.exchange(path='/v1/sessions')
        self.assertEqual(code,200)
        self.assertEqual(payload['sessions'],[])

    def test_reader_may_not_stage(self):
        body=json.dumps({'request_id':'req_'+'a'*32,'chat_id':self.chat,
                         'task_id':'task_'+'b'*32,'kind':'final','body':'test only'})
        code,_=self.exchange('POST','/v1/messages',
                             body=body,extra={'Content-Type':'application/json'})
        self.assertEqual(code,403)
        self.assertEqual(list((self.pending/'message').glob('*.json')),[])

    def test_writer_stages_and_idempotent_receipt_over_tls(self):
        rid='req_'+'c'*32
        body=json.dumps({'request_id':rid,'chat_id':self.chat,
                         'task_id':'task_'+'d'*32,'kind':'final','body':'test'})
        first=self.exchange('POST','/v1/messages',token='writer',
                            body=body,extra={'Content-Type':'application/json'})
        replay=self.exchange('POST','/v1/messages',token='writer',
                             body=body,extra={'Content-Type':'application/json'})
        self.assertEqual(first[0],202)
        self.assertEqual(replay[0],200)
        self.assertEqual(len(list((self.pending/'message').glob('*.json'))),1)
        code,payload=self.exchange('GET','/v1/requests/'+rid,token='writer')
        self.assertEqual(code,200)
        self.assertEqual(payload['state'],'staged_only')

    def test_host_rejects_loopback_over_tls(self):
        self.assertEqual(self.exchange(host='127.0.0.1:'+str(self.port))[0],403)

    def test_browser_origin_rejected(self):
        self.assertEqual(self.exchange(extra={'Origin':'https://other.invalid'})[0],403)

    def test_query_rejected(self):
        self.assertEqual(self.exchange(path='/v1/health?foo=1')[0],404)

    def test_wrong_ca_rejected(self):
        with self.assertRaises(ssl.SSLError):
            self.exchange(ca=ssl.create_default_context())

    def test_wrong_sni_and_san_rejected(self):
        with self.assertRaises(ssl.SSLError):
            self.exchange(dns='wrong.invalid')

    def test_plaintext_never_parsed_as_http(self):
        with socket.create_connection(('127.0.0.1',self.port),timeout=2) as raw:
            raw.settimeout(1)
            raw.sendall(b'GET /v1/health HTTP/1.1\r\nHost: fortis-observatory-api\r\n\r\n')
            try:
                response=raw.recv(128)
            except (OSError,TimeoutError):
                response=b''
        self.assertFalse(response.startswith(b'HTTP/'))

    def test_key_group_read_refused(self):
        self.key.chmod(0o640)
        with self.assertRaisesRegex(ValueError,'tls_file_owner_or_mode_refused'):
            self.api.https_server(self.api_gateway,'127.0.0.1',0,self.cert,self.key)

    def test_key_symlink_refused(self):
        symlink=self.key.with_name('linked-key.pem')
        symlink.symlink_to(self.key)
        with self.assertRaisesRegex(ValueError,'tls_file_owner_or_mode_refused'):
            self.api.https_server(self.api_gateway,'127.0.0.1',0,self.cert,symlink)

    def test_wrong_dns_policy_refused(self):
        with self.assertRaisesRegex(ValueError,'tls_hostname_refused'):
            self.api.https_server(self.api_gateway,'127.0.0.1',0,self.cert,self.key,
                                  hostname='unapproved.local')

    def test_cli_requires_tls_material_and_443(self):
        script=str(verify_source()/'gateway.py')
        basics=['--archive',str(self.cert.parent/'archive'),
                '--pending-root',str(self.pending),'--receipts',str(self.receipts),
                '--clients',str(self.cert.parent/'clients.json')]
        without=subprocess.run([sys.executable,script,*basics],
                                capture_output=True,text=True,timeout=5)
        self.assertEqual(without.returncode,2)
        self.assertIn('--tls-cert',without.stderr)
        old_port=subprocess.run([sys.executable,script,*basics,
                                 '--tls-cert',str(self.cert),'--tls-key',str(self.key),
                                 '--port','18756'],
                                capture_output=True,text=True,timeout=5)
        self.assertEqual(old_port.returncode,2)
        self.assertIn('invalid_https_bind_or_port',old_port.stderr)


if __name__ == '__main__':
    unittest.main()
