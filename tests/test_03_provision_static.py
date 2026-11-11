"""No provision.main() execution: its absolute /data and chown/chmod are unsafe on host."""
import ast
import unittest
from _helpers import verify_source


class ProvisionContractTests(unittest.TestCase):
    def test_provision_source_parses_and_has_guarded_main(self):
        tree = ast.parse((verify_source(("provision.py",)) / "provision.py").read_bytes())
        self.assertTrue(any(isinstance(n, ast.FunctionDef) and n.name == "main"
                            for n in tree.body))
        self.assertTrue(any(isinstance(n, ast.If) and
                            "__main__" in ast.unparse(n.test) for n in tree.body))

    def test_provision_requires_explicit_disposable_volume_fixture(self):
        text = (verify_source(("provision.py",)) / "provision.py").read_text(encoding="utf-8")
        self.assertIn('Path("/tmp/clients.json")', text)
        self.assertIn('Path("/data")', text)
        self.assertIn("os.chown", text)
        self.assertIn("os.chmod", text)
        # This is a source-contract check, NOT execution against a mounted volume.


if __name__ == "__main__":
    unittest.main()
