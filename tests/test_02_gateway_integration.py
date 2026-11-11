"""Real five-module integration characterization. POSIX only; NO production data.

Never run this script from inside an existing running Observatory container.
Tests only write to tempfile.TemporaryDirectory(), and only read source modules.
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
from _helpers import verify_source


@unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid"),
                     "POSIX UID/mode semantics required; run in separately approved Linux sandbox")
class GatewayIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = verify_source()  # raises before importing any recovered code
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(cls.source))
        try:
            cls.gateway_module = importlib.import_module("gateway")
        finally:
            sys.path.remove(str(cls.source))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ownapi01-synthetic-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.archive = root / "archive"
        self.pending = root / "pending"
        self.receipts = root / "receipts"
        self.config = root / "clients.json"
        for directory in [self.archive, self.pending,
                          self.pending / "event", self.pending / "message", self.receipts]:
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)
        self.token = "Z" * 48  # synthetic only
        self.chat = "synthetic-chat-1"
        client = {"id": "test-client",
                  "token_sha256": hashlib.sha256(self.token.encode("ascii")).hexdigest(),
                  "permissions": ["read:metadata", "read:history", "write:events", "write:messages"],
                  "chats": [self.chat]}
        self.config.write_text(json.dumps({"version": 1, "clients": [client]}), encoding="utf-8")
        self.config.chmod(0o600)
        self.gateway = self.gateway_module.Gateway(
            self.archive, self.pending, self.receipts, self.config)
        self.client = self.gateway.authenticate("Bearer " + self.token)
        self.assertIsNotNone(self.client)

    def message_request(self, request_id="req_" + "a" * 32, body="Synthetic assistant text"):
        return {"request_id": request_id, "chat_id": self.chat,
                "task_id": "task_" + "b" * 32, "kind": "final", "body": body}

    def test_valid_and_invalid_auth(self):
        self.assertIsNone(self.gateway.authenticate(None))
        self.assertIsNone(self.gateway.authenticate("Bearer " + "Y" * 48))
        self.assertEqual(self.client["id"], "test-client")

    def test_scopes_and_permissions(self):
        self.assertTrue(self.gateway.allowed(self.client, "write:messages", self.chat))
        self.assertFalse(self.gateway.allowed(self.client, "write:messages", "foreign-chat-1"))
        self.assertFalse(self.gateway.allowed(self.client, "admin", self.chat))

    def test_new_message_is_staged_only(self):
        receipt, created = self.gateway.stage(self.client, "message", self.message_request())
        self.assertTrue(created)
        self.assertEqual(receipt["state"], "staged_only")
        self.assertEqual(len(list((self.pending / "message").glob("*.json"))), 1)
        self.assertEqual(len(list(self.receipts.glob("*.json"))), 1)
        self.assertFalse((self.archive / "sessions").exists())
        self.assertEqual(self.gateway.receipt(self.client, self.message_request()["request_id"]), receipt)

    def test_same_request_is_idempotent(self):
        original, created = self.gateway.stage(self.client, "message", self.message_request())
        repeated, created_again = self.gateway.stage(self.client, "message", self.message_request())
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(original, repeated)
        self.assertEqual(len(list((self.pending / "message").glob("*.json"))), 1)

    def test_request_id_conflict_refused(self):
        self.gateway.stage(self.client, "message", self.message_request())
        with self.assertRaises(FileExistsError):
            self.gateway.stage(self.client, "message", self.message_request(body="Different text"))
        self.assertEqual(len(list((self.pending / "message").glob("*.json"))), 1)

    def test_wrong_chat_refused_without_file_write(self):
        bad = self.message_request()
        bad["chat_id"] = "foreign-chat-1"
        with self.assertRaises(PermissionError):
            self.gateway.stage(self.client, "message", bad)
        self.assertFalse(list((self.pending / "message").glob("*.json")))
        self.assertFalse(list(self.receipts.glob("*.json")))

    def test_invalid_message_refused_without_write(self):
        bad = self.message_request()
        bad["kind"] = "not-a-valid-kind"
        with self.assertRaises(ValueError):
            self.gateway.stage(self.client, "message", bad)
        self.assertFalse(list((self.pending / "message").glob("*.json")))
        self.assertFalse(list(self.receipts.glob("*.json")))

    def test_event_stages_separately(self):
        req = {"request_id": "req_" + "c" * 32,
               "chat_id": self.chat, "task_id": "task_" + "d" * 32,
               "sequence": 0, "event": "progress", "stage": "testing",
               "summary": "Synthetic progress", "detail": None}
        receipt, created = self.gateway.stage(self.client, "event", req)
        self.assertTrue(created)
        self.assertEqual(receipt["action"], "event")
        self.assertEqual(len(list((self.pending / "event").glob("*.json"))), 1)

    def test_crash_between_pending_and_receipt_exposes_orphan(self):
        # Characterization of an acknowledged failure window, NOT proof of delivery safety.
        original_atomic = self.gateway_module._atomic
        def inject_failure(path, payload):
            if Path(path).parent == self.receipts:
                raise OSError("synthetic crash before receipt")
            return original_atomic(path, payload)
        request = self.message_request()
        with patch.object(self.gateway_module, "_atomic", side_effect=inject_failure):
            with self.assertRaises(OSError):
                self.gateway.stage(self.client, "message", request)
        pending_before_retry = list((self.pending / "message").glob("*.json"))
        self.assertEqual(len(pending_before_retry), 1)
        self.assertFalse(list(self.receipts.glob("*.json")))
        receipt, created = self.gateway.stage(self.client, "message", request)
        self.assertTrue(created)
        self.assertEqual(receipt["state"], "staged_only")
        pending_after_retry = list((self.pending / "message").glob("*.json"))
        self.assertEqual(len(pending_after_retry), 2,
                         "If behavior changes, update idempotency characterization")
        record_ids = {json.loads(p.read_text(encoding="ascii"))["record_id"]
                      for p in pending_after_retry}
        self.assertEqual(len(record_ids), 1, "Retry should reuse downstream logical record ID")

    def test_private_pending_requires_owner_only_permissions(self):
        self.pending.chmod(0o755)
        self.addCleanup(lambda: self.pending.chmod(0o700))
        with self.assertRaisesRegex(ValueError, "directory_owner_or_mode_refused"):
            self.gateway_module.private_directory(self.pending)


if __name__ == "__main__":
    unittest.main()
