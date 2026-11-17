"""Strict source baseline gate for all OWNAPI-01 tests. No writes to source."""
import hashlib
import os
from pathlib import Path

EXPECTED = {
    "gateway.py": (22803, "9a1627decc3a989461b57ae9b5f7a75b93417d65f5e08fe7ca195e4d3ee5f04a"),
    "provision.py": (2110, "4a020eba83027b3ac09618c17cb13ea08923ead869b1de3f8893cd9b128716b3"),
    "store.py": (38372, "d494a44f94b92c294f60277d08f1bf6f5116781a65aa9d24f8c8f8dd5579256b"),
    "repo_messages.py": (10631, "9258d1adb8e61a613c08ab8be1ef75029321288332e089ba76cde7779222fbbe"),
    "repo_pending.py": (8869, "feec7fe2189da1fb7dd9d5ea161220902b4773c60511d102cdbef4d4a519fa09"),
}


def source_root():
    value = os.environ.get("OWNAPI_SOURCE_DIR", "").strip()
    if not value:
        raise RuntimeError("Set OWNAPI_SOURCE_DIR to recovered five-file directory; never to live Docker paths")
    root = Path(value).expanduser().resolve()
    if not root.is_dir():
        raise RuntimeError("Source directory does not exist")
    return root


def verify_source(required=None):
    root = source_root()
    selection = EXPECTED if required is None else {name: EXPECTED[name] for name in required}
    for filename, (size, digest) in selection.items():
        path = root / filename
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("Expected regular file missing: " + filename)
        raw = path.read_bytes()
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError("Source baseline mismatch: " + filename)
    if required is None:
        files = {p.name for p in root.glob("*.py")}
        if files != set(EXPECTED):
            raise RuntimeError("Unexpected/missing Python source filenames")
    return root
