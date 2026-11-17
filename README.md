# Fortis Observatory API — recovered source candidate

OWNAPI-01 historical provenance: five Python modules were originally recovered
byte-for-byte from a previously identified image. OWNAPI-GW-01 now changes
`gateway.py` in a **separate unmerged HTTPS-only source candidate**; the new
candidate size and SHA-256 are pinned by `tests/_helpers.py` and
`tests/test_04_pipeline_synthetic.py`. The other four recovered modules stay
unchanged. Original SHA-256 evidence remains in Git history. This repository is **not** proof of the historical
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

The GitHub workflow runs the 57-test synthetic suite using an isolated Docker
container. A passing workflow is evidence only for the tested source and
environment; it does not activate the Observatory or test live integrations.

## Release gate

No automatic deployment, runtime restart, credential provisioning, registry
push or main-branch commit is provided. Publication follows Fortis typed
Gateway task/PR/CI/owner merge. Live acceptance and rollback are separate.


## OWNAPI-GW-01 HTTPS-only source candidate (not installed)

- Startup **requires** `--tls-cert` and `--tls-key` paths to owner-mounted,
  validated PEM files. `--port` is exactly 443; no plaintext fallback, no
  second HTTP listener. The service DNS authority is fixed to
  `fortis-observatory-api` and TLS SNI must match it.
- The Docker-only **target** has one reviewed `internal:true` bridge and
  **no** `ports` on Windows host; this source/Dockerfile do not create a
  network or authorize Compose deployment. If the container remains attached
  to other networks, wildcard `0.0.0.0:443` is a release STOP.
- The certificate/key mounts are owner-protected, never baked into the image,
  Git, Workfiles or ChatGPT. The unmodified full API, including authorized
  staging POST, is available only behind TLS. Gateway will export two
  separately scoped read-only operations, not full API write capability.
- New synthetic tests cover pinned CA/SAN/SNI, plaintext rejection, Host
  guards, scopes, receipts, idempotency, certificate/key permissions and
  missing TLS start arguments. They require OpenSSL to generate **test-only**
  credentials in temporary directories.
- No production privileges, credentials, networks, volume mounts, port
  publishing, Gateway Apply or HTTP/18756 have been changed. R1 full design,
  independent restore and owner cutover remain separate release gates.
