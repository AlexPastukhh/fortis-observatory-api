import ast
import unittest
from _helpers import EXPECTED, verify_source


class BaselineTests(unittest.TestCase):
    def test_five_exact_source_files(self):
        root = verify_source()
        self.assertEqual({p.name for p in root.glob("*.py")}, set(EXPECTED))

    def test_syntax_for_all_five_files(self):
        root = verify_source()
        for name in EXPECTED:
            with self.subTest(name=name):
                ast.parse((root / name).read_bytes(), filename=name)


if __name__ == "__main__":
    unittest.main()
