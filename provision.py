"""One-shot isolated-volume initialization; invoked only by guarded Windows preflight.

Requires root in a disposable container, no network, dedicated Gateway volume.
Copies *hashed* client allowlist; no raw token is provided to this helper.
"""
import os
from pathlib import Path
import stat
import sys

UID = 1000
GID = 1000


def main():
    source = Path("/tmp/clients.json")
    dest_dir = Path("/data")
    target = dest_dir / "clients.json"
    receipts = dest_dir / "receipts"

    if (not source.is_file() or source.is_symlink() or
            source.stat().st_size > 65536):
        raise ValueError("client_source_unavailable")
    if not dest_dir.is_dir() or dest_dir.is_symlink():
        raise ValueError("private_volume_unavailable")
    raw = source.read_bytes()

    if target.exists() or target.is_symlink():
        if not target.is_file() or target.is_symlink() or target.read_bytes() != raw:
            raise ValueError("existing_client_config_mismatch")
    else:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())

    if receipts.exists() or receipts.is_symlink():
        if not receipts.is_dir() or receipts.is_symlink():
            raise ValueError("unsafe_receipts")
    else:
        receipts.mkdir(mode=0o700)
    for path, mode in ((target, 0o600), (receipts, 0o700)):
        os.chown(path, UID, GID)
        os.chmod(path, mode)
        st = path.stat()
        if st.st_uid != UID or st.st_gid != GID or stat.S_IMODE(st.st_mode) != mode:
            raise ValueError("private_volume_permissions_failed")
    # Private-volume mount root may be root-owned and protected; the
    # non-root runtime only needs traversal of it to enter 0700 receipts.
    os.chmod(dest_dir, 0o755)
    print("GATEWAY_PRIVATE_VOLUME=OK", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        print("GATEWAY_PROVISION_FAILED: " + type(exc).__name__, file=sys.stderr)
        sys.exit(1)
