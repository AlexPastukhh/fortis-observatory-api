"""Pure gateway checks with three intentionally stubbed imports. Not integration tests."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from _helpers import verify_source


class GatewayPureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = verify_source(("gateway.py",)) / "gateway.py"
        stubs = {
            "repo_pending": {"LIMIT": 123, "NAME": re.compile(".*"), "encoded": lambda x: b""},
            "repo_messages": {"RepoMessages": type("DummyRepoMessages", (), {})},
            "store": {"Store": type("DummyStore", (), {}),
                      "_atomic": lambda *a: None,
                      "_dir": lambda p: Path(p).absolute(),
                      "_is_link": lambda p: Path(p).is_symlink()},
        }
        modules = {}
        for name, values in stubs.items():
            module = types.ModuleType(name)
            for key, val in values.items():
                setattr(module, key, val)
            modules[name] = module
        spec = importlib.util.spec_from_file_location("ownapi01_gateway_pure", path)
        mod = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, modules):
            spec.loader.exec_module(mod)
        cls.gw = mod

    def test_strict_json_rejects_duplicate_keys(self):
        with self.assertRaisesRegex(ValueError, "duplicate_json_field"):
            json.loads('{"a": 1, "a": 2}', object_pairs_hook=self.gw.strict_pairs)

    def test_auth_valid_invalid_and_scopes(self):
        token = "Z" * 48  # synthetic, no production credentials
        client = {"id": "test", "hash": hashlib.sha256(token.encode()).hexdigest(),
                  "permissions": frozenset({"read:metadata", "write:messages"}),
                  "scope": "chats", "chats": frozenset({"synthetic-chat-1"})}
        gateway = self.gw.Gateway.__new__(self.gw.Gateway)
        gateway.clients = [client]
        self.assertIsNotNone(gateway.authenticate("Bearer " + token))
        self.assertIsNone(gateway.authenticate("Bearer " + "X" * 48))
        self.assertIsNone(gateway.authenticate("Basic " + token))
        self.assertIsNone(gateway.authenticate("Bearer short"))
        self.assertTrue(gateway.allowed(client, "read:metadata", "synthetic-chat-1"))
        self.assertFalse(gateway.allowed(client, "read:history", "synthetic-chat-1"))
        self.assertFalse(gateway.allowed(client, "write:messages", "foreign-chat-1"))

    def test_config_duplicate_client_fields_refused(self):
        with tempfile.TemporaryDirectory(prefix="ownapi01-pure-") as d:
            path = Path(d) / "clients.json"
            path.write_text('{"version":1,"version":1,"clients":[]}', encoding="utf-8")
            if hasattr(path, "chmod"):
                path.chmod(0o600)
            with self.assertRaises(ValueError):
                self.gw.read_config(path)


if __name__ == "__main__":
    unittest.main()
