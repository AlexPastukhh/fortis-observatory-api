# Fortis Observatory API — recovered source candidate

OWNAPI-01 provenance: five Python modules were recovered byte-for-byte from a
previously identified image; their sizes and SHA-256 values are enforced by
`tests/_helpers.py`. This repository is **not** proof of the historical
Dockerfile, original Git provenance, or a verified production upgrade.

## Modules and tests

Required top-level files:
`gateway.py`, `provision.py`, `store.py`,
`repo_messages.py`, `repo_pending.py`.

Run the included characterization tests in a disposable Linux environment,
with `OWNAPI_SOURCE_DIR` set to the directory containing exactly those five
files. The tests use synthetic data. On 2026-11-11 the owner reported 42/42
passing in a disposable `linux/amd64` Docker image with Python 3.12.16,
Debian 13 and UID 1000.

`Dockerfile.candidate` is a **candidate**, not an independently recovered
historical Dockerfile. Its `BASE_IMAGE` argument has no default and must
be supplied as an immutable digest. Build/CI do not copy credentials,
operational data or volumes into the image. Never run the candidate against
production storage without a separately reviewed deployment/rollback plan.

The GitHub workflow runs the synthetic 42-test suite using an isolated Docker
container. A passing workflow is evidence only for the tested source and
environment; it does not activate the Observatory or test live integrations.

## Release gate

No automatic deployment, runtime restart, credential provisioning, registry
push or main-branch commit is provided. Publication follows Fortis typed
Gateway task/PR/CI/owner merge. Live acceptance and rollback are separate.
