"""Isolated local API for Fortis Observatory's existing Repo archive.

Container: mounts ONLY a read-only Repo archive and the bounded pending-context
inbox. No Windows owner bearer, Notifier pairing, shell execution, or public API.
All write receipts mean STAGED_ONLY, never accepted into archive / ChatGPT.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import ssl
import stat
import threading
import time
from urllib.parse import parse_qs, urlsplit

from repo_pending import LIMIT, NAME, encoded
from repo_messages import RepoMessages
from store import Store, _atomic, _dir, _is_link

ID_CHAT = re.compile(r"[A-Za-z0-9-]{8,100}\Z")
ID_SESSION = re.compile(r"rs_[0-9a-f]{32}\Z")
ID_TASK = re.compile(r"task_[0-9a-f]{32}\Z")
ID_REQUEST = re.compile(r"req_[0-9a-f]{32}\Z")
ID_CLIENT = re.compile(r"[a-z][a-z0-9_-]{2,47}\Z")
ID_SHA = re.compile(r"[0-9a-f]{64}\Z")
VALID_PERMISSIONS = frozenset(("read:metadata", "read:history",
                                "write:events", "write:messages"))
MAX_BODY = 350 * 1024
MAX_RECEIPTS = 20000


def strict_pairs(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("duplicate_json_field")
        data[key] = value
    return data


def private_directory(path):
    path = _dir(Path(path))
    if not path.is_dir() or _is_link(path):
        raise ValueError("directory_unavailable")
    metadata = path.stat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("directory_owner_or_mode_refused")
    return path


def read_config(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError("client_config_unavailable")
    if stat.S_IMODE(path.stat().st_mode) & 0o022:
        raise ValueError("client_config_writable_by_others")
    obj = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_pairs)
    if (not isinstance(obj, dict) or set(obj) != {"version", "clients"} or
            type(obj["version"]) is not int or obj["version"] != 1 or
            not isinstance(obj["clients"], list) or not obj["clients"] or
            len(obj["clients"]) > 32):
        raise ValueError("invalid_client_config")
    result = []
    ids, hashes = set(), set()
    required = {"id", "token_sha256", "permissions", "chats"}
    for c in obj["clients"]:
        if not isinstance(c, dict) or set(c) not in (required, required | {"scope"}):
            raise ValueError("invalid_client_entry")
        scope = c.get("scope", "chats")  # Legacy explicit allowlists remain valid.
        if (not isinstance(c["id"], str) or not ID_CLIENT.fullmatch(c["id"])
                or not isinstance(c["token_sha256"], str) or not ID_SHA.fullmatch(c["token_sha256"])
                or not isinstance(c["permissions"], list) or not c["permissions"]
                or not all(isinstance(p, str) for p in c["permissions"])
                or len(c["permissions"]) != len(set(c["permissions"]))
                or not set(c["permissions"]) <= VALID_PERMISSIONS
                or not isinstance(c["chats"], list)
                or not all(isinstance(chat, str) and ID_CHAT.fullmatch(chat)
                        for chat in c["chats"])
                or len(set(c["chats"])) != len(c["chats"]) or len(c["chats"]) > 200
                or (scope == "all_registered" and
                    (c["id"] != "windows" or c["chats"] != []))
                or (scope == "chats" and not c["chats"])
                or scope not in ("all_registered", "chats")
                or c["id"] in ids or c["token_sha256"] in hashes):
            raise ValueError("invalid_client_entry")
        ids.add(c["id"])
        hashes.add(c["token_sha256"])
        result.append({"id": c["id"], "hash": c["token_sha256"],
                       "permissions": frozenset(c["permissions"]),
                       "scope": scope,
                       "chats": frozenset(c["chats"])})
    return result


class Gateway:
    def __init__(self, archive, pending_root, receipts, config):
        self.archive = _dir(Path(archive))
        if not self.archive.is_dir() or _is_link(self.archive):
            raise ValueError("archive_unavailable")
        self.pending_root = private_directory(pending_root)
        self.inbox = {kind: private_directory(self.pending_root / kind)
                      for kind in ("event", "message")}
        self.receipts = private_directory(receipts)
        self.clients = read_config(config)
        self.lock = threading.RLock()

    def authenticate(self, bearer):
        # All authorized clients must use random, high-entropy opaque tokens.
        if not isinstance(bearer, str) or not bearer.startswith("Bearer "):
            return None
        token = bearer[7:]
        if (not 32 <= len(token) <= 128 or
                not re.fullmatch(r"[A-Za-z0-9_-]+", token)):
            return None
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        found = None
        for client in self.clients:
            if hmac.compare_digest(digest, client["hash"]):
                found = client
        return found

    @staticmethod
    def has_chat_scope(client, chat):
        return client["scope"] == "all_registered" or chat in client["chats"]

    def allowed(self, client, permission, chat):
        if (permission not in client["permissions"] or
                not isinstance(chat, str) or not ID_CHAT.fullmatch(chat) or
                not self.has_chat_scope(client, chat)):
            return False
        if client["scope"] == "all_registered":
            # Host owner scope follows the current registered sessions,
            # including registrations made after client provisioning.
            # It never grants arbitrary/unregistered conversation IDs.
            return any(s["conversation_id"] == chat for s in Store(self.archive).sessions())
        return True

    def session_meta(self, client, sid):
        if not ID_SESSION.fullmatch(sid):
            raise ValueError("invalid_session")
        store = Store(self.archive)
        data = next((s for s in store.sessions()
                     if s["reporting_session_id"] == sid and
                     self.has_chat_scope(client, s["conversation_id"])), None)
        return store, data

    def sessions(self, client):
        store = Store(self.archive)
        return [self._public_session(s) for s in store.sessions()
                if self.has_chat_scope(client, s["conversation_id"])]

    @staticmethod
    def _public_session(s):
        # No session_task/enrollment, observer keys, writer keys or internal paths.
        return {k: s.get(k) for k in
                ("reporting_session_id", "conversation_id", "title", "route",
                 "state", "events_count", "last_task_id", "last_signal_at")}

    @staticmethod
    def _public_event(event):
        return {k: event.get(k) for k in
                ("event_id", "task_id", "sequence", "event", "stage", "summary",
                 "accepted_at", "has_detail", "provenance")}

    def history(self, client, sid, task):
        if not ID_TASK.fullmatch(task):
            raise ValueError("invalid_task")
        store, sess = self.session_meta(client, sid)
        if sess is None:
            raise KeyError("not_found")
        # history() is a read-only path. Do not grant any writer capability.
        reader = RepoMessages(store, Path("/no-message-inbox"), Path("/no-quarantine"))
        return reader.history(sid, task)

    def _receipt_name(self, client, request_id):
        return hashlib.sha256((client["id"] + "\0" + request_id).encode("ascii")).hexdigest()

    def receipt(self, client, request_id):
        if not isinstance(request_id, str) or not ID_REQUEST.fullmatch(request_id):
            raise ValueError("invalid_request_id")
        path = self.receipts / (self._receipt_name(client, request_id) + ".json")
        if not path.exists():
            return None
        if _is_link(path) or not path.is_file() or path.stat().st_size > 1000:
            raise ValueError("unsafe_receipt")
        record = json.loads(path.read_text(encoding="ascii"), object_pairs_hook=strict_pairs)
        if (not isinstance(record, dict) or
                set(record) != {"request_id", "chat_id", "action", "digest", "state"} or
                record["request_id"] != request_id or
                not ID_SHA.fullmatch(record["digest"]) or
                record["state"] != "staged_only"):
            raise ValueError("invalid_receipt")
        if not self.has_chat_scope(client, record["chat_id"]):
            raise PermissionError("scope_refused")
        return record

    def stage(self, client, action, request):
        permission = "write:events" if action == "event" else "write:messages"
        if not isinstance(request, dict) or not isinstance(request.get("chat_id"), str):
            raise ValueError("invalid_request")
        chat = request["chat_id"]
        if not self.allowed(client, permission, chat):
            raise PermissionError("scope_refused")
        expected = ({"request_id", "chat_id", "task_id", "event", "stage",
                     "summary", "sequence", "detail"} if action == "event" else
                    {"request_id", "chat_id", "task_id", "kind", "body"})
        if (set(request) != expected or
                not isinstance(request["request_id"], str) or
                not ID_REQUEST.fullmatch(request["request_id"]) or
                not isinstance(request["task_id"], str) or
                not ID_TASK.fullmatch(request["task_id"])):
            raise ValueError("invalid_request")
        digest = hashlib.sha256(json.dumps(request, sort_keys=True, ensure_ascii=True,
                             separators=(",", ":")).encode("ascii")).hexdigest()
        rid = hashlib.sha256((client["id"] + "\0" + request["request_id"])
                             .encode("ascii")).hexdigest()[:32]
        data = ({"sequence": request["sequence"], "event": request["event"],
                 "stage": request["stage"], "summary": request["summary"],
                 "detail": request["detail"]} if action == "event" else
                {"kind": request["kind"], "body": request["body"]})
        with self.lock:
            previous = self.receipt(client, request["request_id"])
            if previous:
                if previous["digest"] != digest or previous["action"] != action:
                    raise FileExistsError("idempotency_conflict")
                return previous, False
            if len(list(self.receipts.glob("*.json"))) >= MAX_RECEIPTS:
                raise OverflowError("receipt_capacity")
            inbox = self.inbox[action]
            if sum(1 for p in inbox.iterdir() if NAME.fullmatch(p.name)) >= LIMIT:
                raise OverflowError("spool_capacity")
            record = {"version": 1, "action": action, "conversation_id": chat,
                      "task_id": request["task_id"], "record_id": rid,
                      "created_ns": time.time_ns(), "data": data, "binding": None}
            raw = encoded(record)  # Reuse exact Repo pending-context validation.
            filename = f'{record["created_ns"]:020d}-{rid}.json'
            pending = inbox / filename
            _atomic(pending, raw)
            # Durable staging happens before the receipt. If a crash occurs
            # between them, a retry reuses the same downstream event/message ID.
            if pending.exists():
                if _is_link(pending) or pending.read_bytes() != raw:
                    raise OSError("queue_readback_failed")
            receipt = {"request_id": request["request_id"], "chat_id": chat,
                       "action": action, "digest": digest, "state": "staged_only"}
            _atomic(self.receipts / (self._receipt_name(client,request["request_id"]) + ".json"),
                    json.dumps(receipt, ensure_ascii=True, separators=(",", ":")).encode("ascii"))
            return receipt, True


def handler_for(gateway, hostname="fortis-observatory-api", *, https_only=False):
    class Handler(BaseHTTPRequestHandler):
        server_version = "FortisGateway"
        sys_version = ""

        def log_message(self, fmt, *args):
            # Never log request URLs, tokens, chat content, or user messages.
            pass

        def respond(self, code, result):
            payload = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def guard(self):
            # Accept only machine-to-machine clients, never browser-origin requests.
            host = self.headers.get_all("Host", [])
            port = self.server.server_port
            # HTTPS clients may omit the default :443 in Host. In the TLS-only
            # configuration, refuse loopback/other-network authorities even
            # when the Docker IP is reachable from an unintended network.
            allowed_hosts = ({hostname, f"{hostname}:443"} if https_only else
                             {f"127.0.0.1:{port}", f"localhost:{port}",
                              f"{hostname}:{port}"})
            origin = self.headers.get("Origin")
            if (len(host) != 1 or host[0].lower() not in allowed_hosts or origin is not None
                    or self.headers.get("Sec-Fetch-Site")
                    or urlsplit(self.path).netloc or urlsplit(self.path).scheme
                    or urlsplit(self.path).fragment):
                self.respond(403, {"ok": False, "error": "request_origin_refused"})
                return None
            bearer = self.headers.get_all("Authorization", [])
            client = gateway.authenticate(bearer[0]) if len(bearer) == 1 else None
            if client is None:
                self.respond(401, {"ok": False, "error": "client_auth_required"})
            return client

        def do_GET(self):
            client = self.guard()
            if client is None:
                return
            parsed = urlsplit(self.path)
            try:
                if parsed.path == "/v1/health" and not parsed.query:
                    self.respond(200, {"ok": True, "service": "fortis-observatory-api",
                                       "mode": "staging_only"})
                    return
                if parsed.path == "/v1/sessions" and not parsed.query:
                    if "read:metadata" not in client["permissions"]:
                        raise PermissionError("read_denied")
                    self.respond(200, {"ok": True, "sessions": gateway.sessions(client)})
                    return
                match = re.fullmatch(r"/v1/sessions/(rs_[0-9a-f]{32})/events", parsed.path)
                if match and not parsed.query:
                    if "read:metadata" not in client["permissions"]:
                        raise PermissionError("read_denied")
                    _, sess = gateway.session_meta(client, match.group(1))
                    if sess is None:
                        raise KeyError("session_unavailable")
                    self.respond(200, {"ok": True, "session": match.group(1),
                                       "events": [gateway._public_event(e)
                                                  for e in sess["events"][-200:]]})
                    return
                if parsed.path == "/v1/history":
                    if "read:history" not in client["permissions"]:
                        raise PermissionError("read_denied")
                    params = parse_qs(parsed.query, strict_parsing=True)
                    if (set(params) != {"session", "task"} or
                            any(len(v) != 1 for v in params.values())):
                        raise ValueError("invalid_query")
                    self.respond(200, {"ok": True, **gateway.history(
                        client, params["session"][0], params["task"][0])})
                    return
                match = re.fullmatch(r"/v1/requests/(req_[0-9a-f]{32})", parsed.path)
                if match and not parsed.query:
                    saved = gateway.receipt(client, match.group(1))
                    if saved is None:
                        raise KeyError("receipt_not_found")
                    self.respond(200, {"ok": True, "request_id": saved["request_id"],
                                       "state": saved["state"]})
                    return
                self.respond(404, {"ok": False, "error": "route_not_found"})
            except PermissionError:
                self.respond(403, {"ok": False, "error": "permission_refused"})
            except KeyError:
                self.respond(404, {"ok": False, "error": "not_found"})
            except (ValueError, UnicodeError, TypeError):
                self.respond(400, {"ok": False, "error": "invalid_request"})
            except OSError:
                self.respond(503, {"ok": False, "error": "archive_unavailable"})

        def do_POST(self):
            client = self.guard()
            if client is None:
                return
            parsed = urlsplit(self.path)
            if parsed.query or parsed.path not in ("/v1/events", "/v1/messages"):
                self.respond(404, {"ok": False, "error": "route_not_found"})
                return
            try:
                lengths = self.headers.get_all("Content-Length", [])
                types = self.headers.get_all("Content-Type", [])
                if (len(lengths) != 1 or not lengths[0].isascii() or
                        not lengths[0].isdigit() or self.headers.get("Transfer-Encoding") or
                        len(types) != 1 or types[0].lower() != "application/json"):
                    raise ValueError("bad_framing")
                length = int(lengths[0])
                if length < 1 or length > MAX_BODY:
                    raise ValueError("bad_size")
                request = json.loads(self.rfile.read(length).decode("utf-8"),
                                     object_pairs_hook=strict_pairs)
                kind = "event" if parsed.path == "/v1/events" else "message"
                receipt, created = gateway.stage(client, kind, request)
                self.respond(202 if created else 200,
                             {"ok": True, "request_id": receipt["request_id"],
                              "state": "staged_only", "created": created})
            except PermissionError:
                self.respond(403, {"ok": False, "error": "permission_refused"})
            except FileExistsError:
                self.respond(409, {"ok": False, "error": "idempotency_conflict"})
            except OverflowError:
                self.respond(429, {"ok": False, "error": "queue_capacity"})
            except (ValueError, TypeError, KeyError, UnicodeError):
                self.respond(400, {"ok": False, "error": "invalid_request"})
            except OSError:
                self.respond(503, {"ok": False, "error": "staging_unavailable"})

        def do_OPTIONS(self):
            self.respond(405, {"ok": False, "error": "no_cors"})

        def do_PUT(self):
            self.respond(405, {"ok": False, "error": "method_refused"})

        do_DELETE = do_PUT
        do_PATCH = do_PUT

    return Handler



def _tls_file(path, *, private):
    # Neither the certificate nor the private key is ever emitted in logs.
    path = Path(path)
    metadata = path.lstat()
    if (path.parent.is_symlink() or path.parent.parent.is_symlink()
            or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or (stat.S_IMODE(metadata.st_mode) & (0o077 if private else 0o022))):
        raise ValueError("tls_file_owner_or_mode_refused")
    return path


def https_server(gateway, bind, port, certificate, private_key,
                 *, hostname="fortis-observatory-api"):
    """One API process, one direct TLS listener; no plaintext fallback."""
    if not hostname or hostname != "fortis-observatory-api":
        raise ValueError("tls_hostname_refused")
    certificate = _tls_file(certificate, private=False)
    private_key = _tls_file(private_key, private=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(str(certificate), str(private_key))

    def check_sni(socket, server_name, active_context):
        if server_name != hostname:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME

    context.set_servername_callback(check_sni)
    server = ThreadingHTTPServer(
        (bind, port), handler_for(gateway, hostname, https_only=True))
    server.daemon_threads = True
    try:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    except BaseException:
        server.server_close()
        raise
    return server


def main():
    parser = argparse.ArgumentParser(description="Private Fortis Observatory API Gateway")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--pending-root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    parser.add_argument("--clients", type=Path, required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--tls-cert", type=Path, required=True)
    parser.add_argument("--tls-key", type=Path, required=True)
    args = parser.parse_args()
    if args.port != 443 or args.bind not in ("127.0.0.1", "0.0.0.0"):
        parser.error("invalid_https_bind_or_port")
    gateway = Gateway(args.archive, args.pending_root, args.receipts, args.clients)
    server = https_server(gateway, args.bind, args.port,
                          args.tls_cert, args.tls_key)
    print("FORTIS_OBSERVATORY_HTTPS_READY tls=true staging_only=true", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
