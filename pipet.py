#!/usr/bin/env python3
"""pipet - authenticated remote command execution over a cocoon pastebin.

Two roles share one script:

  agent   signs a request and publishes it as a paste
  remote  polls the pastebin, verifies the SSH signature, runs the command,
          and publishes the result as another paste

Requests are routed by title:

  pipet:<remote>:req:<request_id>
  pipet:<remote>:res:<request_id>
  pipet:presence:<remote>

A remote can optionally publish signed presence announcements, which the agent
discovers with `pipet remotes`. The paste body is a small JSON envelope holding
the exact signed bytes and an armored OpenSSH signature. Verification is
delegated to `ssh-keygen -Y verify`, so only Python, `requests`, and OpenSSH are
required.

See `pipet.py <command> --help` for usage.
"""

import argparse
import base64
import contextlib
import fcntl
import getpass
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

try:
    import requests
except ImportError as exc:
    raise SystemExit(
        "pipet requires the 'requests' package (pip install requests)"
    ) from exc

PROTOCOL_VERSION = 1
DEFAULT_PASTE_URL = "https://cocoon.sereph.us"
DEFAULT_NAMESPACE = "pipet"
USER_AGENT = "pipet/1"
DEFAULT_KEY = "~/.ssh/id_ed25519"
DEFAULT_ALLOWED_SIGNERS = "~/.config/pipet/allowed_signers"
DEFAULT_REMOTE_SIGNERS = "~/.config/pipet/remotes_allowed_signers"
DEFAULT_TIMEOUT = 60
DEFAULT_EXPIRES = 300
DEFAULT_INTERVAL = 2.0
DEFAULT_MAX_TIMEOUT = 300
DEFAULT_MAX_OUTPUT = 1_000_000
DEFAULT_MAX_PAGES = 50
DEFAULT_HTTP_TIMEOUT = 30.0
DEFAULT_ANNOUNCE_INTERVAL = 300
DEFAULT_ANNOUNCE_TTL = 900
PRESENCE_INFIX = "pipet:presence:"
CLOCK_LEEWAY = 60
EXPIRY_LEEWAY = 5
STATE_TTL = 7 * 24 * 3600

_REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$")
_REQUEST_ID_RE = re.compile(r"^[0-9a-f]{16,64}$")


class PipetError(Exception):
    """A permanent error that should be shown to the user."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class TransientError(PipetError):
    """A temporary error; callers may retry later."""


def eprint(*args):
    print(*args, file=sys.stderr, flush=True)


def log(message, verbose_only=False, verbose=False):
    if verbose_only and not verbose:
        return
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    eprint(f"{stamp} pipet: {message}")


def die(message, code=1):
    eprint(f"pipet: {message}")
    raise SystemExit(code)


def check_remote(remote):
    if not isinstance(remote, str) or not _REMOTE_RE.match(remote):
        raise PipetError(
            "invalid remote name (use 1-64 characters: letters, digits, '.', '-')"
        )
    return remote


def req_title(remote, request_id):
    return f"pipet:{remote}:req:{request_id}"


def res_title(remote, request_id):
    return f"pipet:{remote}:res:{request_id}"


def remote_query(remote):
    return f"pipet:{remote}:"


def presence_title(remote):
    return PRESENCE_INFIX + remote


def rfc3339(timestamp):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))


def normalize_base(url):
    url = (url or "").strip().rstrip("/")
    for suffix in ("/api/paste", "/api/pastes", "/api"):
        if url.endswith(suffix):
            url = url[: -len(suffix)].rstrip("/")
            break
    if not url.startswith(("http://", "https://")):
        raise PipetError(f"paste URL must start with http:// or https://: {url!r}")
    return url


HTTP_CLIENTS = ("auto", "requests", "curl")


def resolve_http_client(value):
    name = (value or "requests").strip().lower()
    if name not in HTTP_CLIENTS:
        raise PipetError(f"invalid http client {value!r}; use auto, requests, or curl")
    if name == "auto":
        return "curl" if shutil.which("curl") else "requests"
    if name == "curl" and shutil.which("curl") is None:
        raise PipetError("curl not found; install curl or use --http-client requests")
    return name


def canonical_bytes(obj):
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def short_body(data):
    text = data.decode("utf-8", "replace").strip()
    return text[:300] if text else "(empty response)"


class Cocoon:
    """Minimal client for the cocoon HTTP API."""

    def __init__(
        self,
        base_url,
        http_timeout=DEFAULT_HTTP_TIMEOUT,
        retries=3,
        http_client="requests",
    ):
        self.base = normalize_base(base_url)
        self.http_timeout = max(float(http_timeout), 1.0)
        self.retries = retries
        self.http_client = resolve_http_client(http_client)
        self._session = None

    def _get_session(self):
        if self._session is None:
            session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=8)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self._session = session
        return self._session

    def close(self):
        if self._session is not None:
            self._session.close()
            self._session = None

    def _request(self, method, path, body=None, headers=None, params=None):
        url = self.base + path
        hdrs = {"User-Agent": USER_AGENT}
        if headers:
            hdrs.update(headers)
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                status, data = self._attempt(method, url, body, hdrs, params)
            except TransientError as exc:
                last_error = exc
                if attempt < self.retries:
                    time.sleep(min(2**attempt, 5))
                    continue
                raise
            if status >= 500 and attempt < self.retries:
                last_error = f"HTTP {status}"
                time.sleep(min(2**attempt, 5))
                continue
            return status, data
        raise TransientError(f"{method} {url}: {last_error}")

    def _attempt(self, method, url, body, headers, params):
        if self.http_client == "curl":
            return self._attempt_curl(method, url, body, headers, params)
        return self._attempt_requests(method, url, body, headers, params)

    def _attempt_requests(self, method, url, body, headers, params):
        try:
            response = self._get_session().request(
                method,
                url,
                data=body,
                headers=headers,
                params=params,
                timeout=self.http_timeout,
            )
        except requests.exceptions.RequestException as exc:
            raise TransientError(f"{method} {url}: {exc}") from exc
        return response.status_code, response.content

    def _attempt_curl(self, method, url, body, headers, params):
        args = [
            "curl",
            "-sS",
            "-L",
            "--max-time",
            str(int(self.http_timeout)),
            "-o",
            "-",
            "-w",
            "\n%{http_code}",
            "-A",
            headers.get("User-Agent", USER_AGENT),
        ]
        for key, value in headers.items():
            if key.lower() == "user-agent":
                continue
            args.extend(["-H", f"{key}: {value}"])
        if method != "GET":
            args.extend(["-X", method])
        if method == "GET" and params:
            args.append("--get")
            for key, value in params.items():
                args.extend(["--data-urlencode", f"{key}={value}"])
        if body is not None:
            args.extend(["--data-binary", "@-"])
        args.append(url)
        try:
            proc = subprocess.run(
                args,
                input=body,
                capture_output=True,
                timeout=self.http_timeout + 10,
                check=False,
            )
        except FileNotFoundError as exc:
            raise PipetError(
                "curl not found; install curl or use --http-client requests"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise TransientError(f"{method} {url}: curl timed out") from exc
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            raise TransientError(
                f"{method} {url}: curl failed ({proc.returncode}): {detail}"
            )
        body_bytes, sep, status_bytes = proc.stdout.rpartition(b"\n")
        if not sep:
            raise TransientError(f"{method} {url}: curl produced no status")
        try:
            status = int(status_bytes.strip())
        except ValueError as exc:
            raise TransientError(
                f"{method} {url}: invalid curl status {status_bytes!r}"
            ) from exc
        if status == 0:
            raise TransientError(f"{method} {url}: curl could not reach the server")
        return status, body_bytes

    def create_paste(self, content, title):
        body = json.dumps(
            {"content": content, "title": title, "private": False}
        ).encode("utf-8")
        status, data = self._request(
            "POST", "/api/paste", body, {"Content-Type": "application/json"}
        )
        if status not in (200, 201):
            raise PipetError(
                f"create paste failed: HTTP {status}: {short_body(data)}",
                status=status,
            )
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TransientError(f"invalid create response: {exc}") from exc

    def list_pastes(self, query=None, page=1, per_page=100, since=None):
        params = {
            "page": str(page),
            "per_page": str(per_page),
            "status": "all",
            "sort": "created_at",
            "order": "desc",
        }
        if query:
            params["q"] = query
        if since:
            params["from"] = since
        status, data = self._request("GET", "/api/pastes", params=params)
        if status != 200:
            if status >= 500:
                raise TransientError(
                    f"list pastes failed: HTTP {status}: {short_body(data)}",
                    status=status,
                )
            raise PipetError(
                f"list pastes failed: HTTP {status}: {short_body(data)}",
                status=status,
            )
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TransientError(f"invalid list response: {exc}") from exc

    def iter_pastes(self, query, max_pages=DEFAULT_MAX_PAGES, since=None):
        seen = set()
        for page in range(1, max_pages + 1):
            listing = self.list_pastes(query=query, page=page, since=since)
            pastes = listing.get("pastes") or []
            for paste in pastes:
                paste_id = paste.get("id")
                if not paste_id or paste_id in seen:
                    continue
                seen.add(paste_id)
                yield paste
            if not listing.get("has_next"):
                return

    def find_by_title(self, title, query=None, max_pages=DEFAULT_MAX_PAGES):
        for paste in self.iter_pastes(query or title, max_pages=max_pages):
            if paste.get("title") == title:
                return paste
        return None

    def read_paste(self, paste_id, reveal_retries=3):
        path = "/p/" + requests.utils.quote(paste_id, safe="")
        for attempt in range(reveal_retries + 1):
            status, data = self._request("GET", path)
            if status == 200:
                return data.decode("utf-8", "replace")
            if status == 425:
                if attempt < reveal_retries:
                    time.sleep(1)
                    continue
                raise TransientError(
                    f"paste {paste_id} is not revealed yet", status=425
                )
            if status == 404:
                raise PipetError(f"paste {paste_id} not found", status=404)
            if status >= 500:
                raise TransientError(
                    f"read paste {paste_id} failed: HTTP {status}", status=status
                )
            raise PipetError(
                f"read paste {paste_id} failed: HTTP {status}: {short_body(data)}",
                status=status,
            )
        raise TransientError(f"paste {paste_id} is not revealed yet", status=425)


# ---------------------------------------------------------------------------
# Signing and envelopes
# ---------------------------------------------------------------------------


def ssh_sign(payload_bytes, key_path, namespace):
    key_path = os.path.expanduser(key_path)
    if not os.path.exists(key_path):
        raise PipetError(f"SSH private key not found: {key_path}")
    with tempfile.TemporaryDirectory(prefix="pipet-sign-") as tmp:
        message_path = os.path.join(tmp, "payload")
        with open(message_path, "wb") as handle:
            handle.write(payload_bytes)
        try:
            proc = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "sign",
                    "-f",
                    key_path,
                    "-n",
                    namespace,
                    message_path,
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
            )
        except FileNotFoundError as exc:
            raise PipetError("ssh-keygen not found; install OpenSSH") from exc
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            raise PipetError(f"ssh-keygen sign failed: {detail or proc.returncode}")
        with open(message_path + ".sig", "r", encoding="utf-8") as handle:
            return handle.read()


def ssh_verify(payload_bytes, signature, allowed_signers, signer, namespace):
    allowed_signers = os.path.expanduser(allowed_signers)
    if not os.path.exists(allowed_signers):
        raise PipetError(f"allowed_signers file not found: {allowed_signers}")
    with tempfile.TemporaryDirectory(prefix="pipet-verify-") as tmp:
        signature_path = os.path.join(tmp, "signature")
        with open(signature_path, "w", encoding="utf-8") as handle:
            handle.write(signature)
        try:
            proc = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    allowed_signers,
                    "-I",
                    signer,
                    "-n",
                    namespace,
                    "-s",
                    signature_path,
                ],
                input=payload_bytes,
                capture_output=True,
                check=False,
            )
        except FileNotFoundError as exc:
            raise PipetError("ssh-keygen not found; install OpenSSH") from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()
            raise PipetError(f"signature verification failed: {detail}")


def make_envelope(payload_bytes, signature):
    envelope = {
        "v": PROTOCOL_VERSION,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signature": signature,
    }
    return json.dumps(envelope, indent=2, sort_keys=True) + "\n"


def parse_envelope(text):
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PipetError(f"malformed request envelope: {exc}") from exc
    if not isinstance(envelope, dict):
        raise PipetError("malformed request envelope: not an object")
    if envelope.get("v") != PROTOCOL_VERSION:
        raise PipetError(f"unsupported protocol version: {envelope.get('v')!r}")
    encoded = envelope.get("payload")
    signature = envelope.get("signature")
    if not isinstance(encoded, str) or not isinstance(signature, str):
        raise PipetError("malformed request envelope: missing payload or signature")
    try:
        payload_bytes = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise PipetError(f"malformed payload encoding: {exc}") from exc
    return payload_bytes, signature


# ---------------------------------------------------------------------------
# Configuration plumbing
# ---------------------------------------------------------------------------


def load_config(path):
    if not path:
        return {}
    path = os.path.expanduser(path)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise PipetError(f"config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PipetError(f"invalid config file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PipetError(f"config file {path} must contain a JSON object")
    return data


def opt(args, config, key, default=None, section=None):
    value = getattr(args, key, None)
    if value is not None:
        return value
    scopes = []
    if section:
        scopes.append(config.get(section, {}))
    scopes.append(config)
    for scope in scopes:
        if isinstance(scope, dict) and scope.get(key) is not None:
            return scope[key]
    return default


def state_path_default():
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state"
    )
    return os.path.join(base, "pipet", "state.json")


def make_cocoon(args, config, base_url, section=None):
    return Cocoon(
        base_url,
        http_timeout=float(
            opt(args, config, "http_timeout", DEFAULT_HTTP_TIMEOUT, section=section)
        ),
        http_client=opt(
            args,
            config,
            "http_client",
            os.environ.get("PIPET_HTTP_CLIENT", "requests"),
            section=section,
        ),
    )


# ---------------------------------------------------------------------------
# Agent commands
# ---------------------------------------------------------------------------


def cmd_submit(args):
    config = load_config(args.config)
    remote = check_remote(opt(args, config, "remote", section="agent") or "")
    base_url = opt(
        args,
        config,
        "paste_url",
        os.environ.get("PIPET_PASTE_URL", DEFAULT_PASTE_URL),
    )
    namespace = opt(
        args, config, "namespace", os.environ.get("PIPET_NAMESPACE", DEFAULT_NAMESPACE)
    )
    key = opt(
        args,
        config,
        "key",
        os.environ.get("PIPET_SSH_KEY", DEFAULT_KEY),
        section="agent",
    )
    signer = opt(
        args,
        config,
        "signer",
        os.environ.get("PIPET_SIGNER", getpass.getuser()),
        section="agent",
    )
    if not signer or any(ch.isspace() for ch in signer):
        raise PipetError("signer must be a non-empty string without whitespace")
    timeout = int(opt(args, config, "timeout", DEFAULT_TIMEOUT, section="agent"))
    expires = int(opt(args, config, "expires", DEFAULT_EXPIRES, section="agent"))
    max_output = int(
        opt(args, config, "max_output_bytes", DEFAULT_MAX_OUTPUT, section="agent")
    )
    cwd = opt(args, config, "cwd", None, section="agent")

    command = args.command
    if command == "-":
        command = sys.stdin.read()
    if not command or not command.strip():
        raise PipetError("command is empty")

    request_id = args.request_id or secrets.token_hex(12)
    if not _REQUEST_ID_RE.match(request_id):
        raise PipetError("request id must be 16-64 lowercase hex characters")

    title = req_title(remote, request_id)
    cocoon = make_cocoon(args, config, base_url, section="agent")

    existing = cocoon.find_by_title(title, query=remote_query(remote))
    if existing:
        log(f"request {request_id} already exists as paste {existing['id']}")
        if args.json:
            print(
                json.dumps(
                    {
                        "request_id": request_id,
                        "paste_id": existing["id"],
                        "url": existing.get("url"),
                        "title": title,
                        "reused": True,
                    },
                    indent=2,
                )
            )
        else:
            print(request_id)
        return 0

    created_at = int(time.time())
    payload = {
        "v": PROTOCOL_VERSION,
        "kind": "request",
        "remote": remote,
        "request_id": request_id,
        "signer": signer,
        "created_at": created_at,
        "expires_at": created_at + max(1, expires),
        "timeout": max(1, timeout),
        "max_output_bytes": max(1024, max_output),
        "command": command,
    }
    if cwd:
        payload["cwd"] = cwd

    payload_bytes = canonical_bytes(payload)
    signature = ssh_sign(payload_bytes, key, namespace)
    envelope = make_envelope(payload_bytes, signature)
    created = cocoon.create_paste(envelope, title)

    if args.json:
        print(
            json.dumps(
                {
                    "request_id": request_id,
                    "paste_id": created.get("id"),
                    "url": created.get("url"),
                    "title": title,
                    "reused": False,
                },
                indent=2,
            )
        )
    else:
        print(request_id)
        log(f"submitted request {request_id} to {remote} as paste {created.get('id')}")
        if created.get("url"):
            log(f"request URL: {created['url']}")
    return 0


def decoded_result(result):
    stdout = base64.b64decode(result.get("stdout_b64") or "")
    stderr = base64.b64decode(result.get("stderr_b64") or "")
    return stdout, stderr


def result_exit_code(result):
    if result.get("timed_out"):
        return 124
    error = result.get("error")
    code = result.get("exit_code")
    sig = result.get("signal")
    if isinstance(code, int) and not isinstance(code, bool):
        return max(0, min(255, code))
    if isinstance(sig, int) and not isinstance(sig, bool) and sig > 0:
        return min(255, 128 + sig)
    if error:
        return 1
    return 0


def verify_result(result, request_id, remote, allowed_signers, namespace):
    if not isinstance(result, dict) or result.get("kind") != "result":
        raise PipetError("result paste does not contain a result object")
    if result.get("request_id") != request_id:
        raise PipetError("result is for a different request")
    if result.get("remote") != remote:
        raise PipetError("result is for a different remote")
    signature = result.get("signature")
    signer = result.get("signed_by")
    if not isinstance(signature, str) or not signature.strip():
        raise PipetError("result is not signed")
    if not isinstance(signer, str) or not signer or any(ch.isspace() for ch in signer):
        raise PipetError("result has an invalid signer identity")
    unsigned = {key: value for key, value in result.items() if key != "signature"}
    ssh_verify(
        canonical_bytes(unsigned),
        signature,
        allowed_signers,
        signer,
        namespace,
    )
    return result


def emit_result(result, as_json):
    if not isinstance(result, dict) or result.get("kind") != "result":
        raise PipetError("result paste does not contain a result object")
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    stdout, stderr = decoded_result(result)
    if stdout:
        sys.stdout.buffer.write(stdout)
        sys.stdout.buffer.flush()
    if stderr:
        sys.stderr.buffer.write(stderr)
        sys.stderr.buffer.flush()

    status = []
    status.append(f"request {result.get('request_id')}")
    status.append(f"remote {result.get('remote')}")
    if result.get("signed_by"):
        status.append(f"signed by {result['signed_by']}")
    if result.get("timed_out"):
        status.append("timed out")
    if result.get("signal"):
        status.append(f"signal {result['signal']}")
    if isinstance(result.get("exit_code"), int):
        status.append(f"exit {result['exit_code']}")
    if result.get("stdout_truncated") or result.get("stderr_truncated"):
        status.append("output truncated")
    if result.get("error"):
        status.append(f"error: {result['error']}")
    log("; ".join(status))
    return result_exit_code(result)


def cmd_result(args):
    config = load_config(args.config)
    remote = check_remote(opt(args, config, "remote", section="agent") or "")
    base_url = opt(
        args,
        config,
        "paste_url",
        os.environ.get("PIPET_PASTE_URL", DEFAULT_PASTE_URL),
    )
    namespace = opt(
        args,
        config,
        "namespace",
        os.environ.get("PIPET_NAMESPACE", DEFAULT_NAMESPACE),
    )
    wait = bool(opt(args, config, "wait", False, section="agent"))
    wait_timeout = float(opt(args, config, "wait_timeout", 300, section="agent"))
    interval = float(opt(args, config, "interval", DEFAULT_INTERVAL, section="agent"))
    max_pages = int(opt(args, config, "max_pages", DEFAULT_MAX_PAGES))
    no_verify = bool(opt(args, config, "no_verify", False, section="agent"))
    verbose = bool(opt(args, config, "verbose", False, section="agent"))
    allowed_signers = os.path.expanduser(
        str(
            opt(
                args,
                config,
                "allowed_signers",
                DEFAULT_REMOTE_SIGNERS,
                section="agent",
            )
        )
    )
    if not no_verify and not os.path.exists(allowed_signers):
        raise PipetError(
            f"trusted remote signers file not found: {allowed_signers} "
            "(create it with 'pipet pubkey' or pass --no-verify)"
        )
    cocoon = make_cocoon(args, config, base_url, section="agent")

    request_id = args.request_id
    if not _REQUEST_ID_RE.match(request_id):
        raise PipetError("request id must be 16-64 lowercase hex characters")
    title = res_title(remote, request_id)
    deadline = time.monotonic() + max(0.0, wait_timeout)

    while True:
        try:
            metas = list(cocoon.iter_pastes(title, max_pages=max_pages))
        except TransientError as exc:
            if not wait:
                raise
            log(f"poll failed, retrying: {exc}")
            metas = []
        for meta in metas:
            if meta.get("title") != title:
                continue
            try:
                text = cocoon.read_paste(meta["id"])
            except TransientError as exc:
                if not wait:
                    raise
                log(f"could not read result {meta['id']}: {exc}")
                continue
            try:
                result = json.loads(text)
            except json.JSONDecodeError as exc:
                log(
                    f"ignoring malformed result {meta['id']}: {exc}",
                    verbose_only=True,
                    verbose=verbose,
                )
                continue
            if not isinstance(result, dict) or result.get("kind") != "result":
                continue
            if not no_verify:
                try:
                    verify_result(
                        result,
                        request_id,
                        remote,
                        allowed_signers,
                        namespace,
                    )
                except PipetError as exc:
                    log(
                        f"ignoring unverified result {meta['id']}: {exc}",
                        verbose_only=True,
                        verbose=verbose,
                    )
                    continue
            return emit_result(result, args.json)
        if not wait:
            raise PipetError(f"no valid result yet for request {request_id}")
        if time.monotonic() >= deadline:
            raise PipetError(f"timed out waiting for result of request {request_id}")
        time.sleep(max(0.2, interval))


def cmd_remotes(args):
    config = load_config(args.config)
    base_url = opt(
        args,
        config,
        "paste_url",
        os.environ.get("PIPET_PASTE_URL", DEFAULT_PASTE_URL),
    )
    namespace = opt(
        args,
        config,
        "namespace",
        os.environ.get("PIPET_NAMESPACE", DEFAULT_NAMESPACE),
    )
    ttl = max(1, int(opt(args, config, "ttl", DEFAULT_ANNOUNCE_TTL, section="agent")))
    max_pages = int(opt(args, config, "max_pages", DEFAULT_MAX_PAGES))
    no_verify = bool(opt(args, config, "no_verify", False, section="agent"))
    allowed_signers = os.path.expanduser(
        str(
            opt(
                args,
                config,
                "allowed_signers",
                DEFAULT_REMOTE_SIGNERS,
                section="agent",
            )
        )
    )
    if not no_verify and not os.path.exists(allowed_signers):
        raise PipetError(
            f"trusted remote signers file not found: {allowed_signers} "
            "(create it with 'pipet pubkey' or pass --no-verify)"
        )
    cocoon = make_cocoon(args, config, base_url, section="agent")

    now = int(time.time())
    since = rfc3339(now - ttl - CLOCK_LEEWAY)
    found = {}
    skipped = 0
    for meta in cocoon.iter_pastes(PRESENCE_INFIX, max_pages=max_pages, since=since):
        title = meta.get("title") or ""
        if not title.startswith(PRESENCE_INFIX):
            continue
        remote = title[len(PRESENCE_INFIX) :]
        if not _REMOTE_RE.match(remote):
            continue
        try:
            text = cocoon.read_paste(meta["id"])
            payload_bytes, signature = parse_envelope(text)
            payload = json.loads(payload_bytes.decode("utf-8"))
        except TransientError as exc:
            log(f"ignoring presence {meta['id']}: {exc}")
            skipped += 1
            continue
        except (PipetError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            log(f"ignoring presence {meta['id']}: {exc}")
            skipped += 1
            continue
        if not isinstance(payload, dict):
            skipped += 1
            continue
        if (
            payload.get("v") != PROTOCOL_VERSION
            or payload.get("kind") != "presence"
            or payload.get("remote") != remote
        ):
            skipped += 1
            continue
        signer = payload.get("signer")
        if (
            not isinstance(signer, str)
            or not signer
            or any(ch.isspace() for ch in signer)
        ):
            skipped += 1
            continue
        created_at = payload.get("created_at")
        expires_at = payload.get("expires_at")
        if type(created_at) is not int or type(expires_at) is not int:
            skipped += 1
            continue
        if created_at > now + CLOCK_LEEWAY or expires_at < now:
            continue

        verified = False
        if not no_verify:
            try:
                ssh_verify(
                    payload_bytes,
                    signature,
                    allowed_signers,
                    signer,
                    namespace,
                )
            except PipetError as exc:
                log(
                    f"ignoring unverified presence {meta['id']} ({remote}): {exc}",
                    verbose_only=True,
                    verbose=args.verbose,
                )
                skipped += 1
                continue
            verified = True

        interval = payload.get("interval")
        max_timeout = payload.get("max_timeout")
        max_output_bytes = payload.get("max_output_bytes")
        poll_interval = payload.get("poll_interval")
        cwd = payload.get("cwd")
        hostname = payload.get("hostname")
        label = payload.get("label")
        info = {
            "remote": remote,
            "signer": signer,
            "hostname": hostname if isinstance(hostname, str) else "",
            "label": label if isinstance(label, str) else "",
            "last_seen": created_at,
            "expires_at": expires_at,
            "expires_in": max(0, expires_at - now),
            "interval": interval if type(interval) is int else None,
            "max_timeout": max_timeout if type(max_timeout) is int else None,
            "max_output_bytes": (
                max_output_bytes if type(max_output_bytes) is int else None
            ),
            "poll_interval": (
                poll_interval
                if isinstance(poll_interval, (int, float))
                and not isinstance(poll_interval, bool)
                else None
            ),
            "cwd": cwd if isinstance(cwd, str) else None,
            "verified": verified,
            "paste_id": meta["id"],
        }
        existing = found.get(remote)
        if existing is None or created_at > existing["last_seen"]:
            found[remote] = info

    rows = sorted(found.values(), key=lambda item: item["remote"])
    if args.json:
        print(
            json.dumps(
                {
                    "remotes": rows,
                    "scanned_at": now,
                    "ttl": ttl,
                    "skipped": skipped,
                },
                indent=2,
            )
        )
        return 0
    if not rows:
        eprint(f"pipet: no remotes announced in the last {ttl}s")
        return 0
    print(
        "REMOTE\tLAST_SEEN\tEXPIRES_IN\tMAX_TIMEOUT\tMAX_OUTPUT\t"
        "SIGNER\tHOSTNAME\tSTATUS"
    )
    for row in rows:
        max_timeout = row["max_timeout"]
        max_output = row["max_output_bytes"]
        print(
            f"{row['remote']}\t{rfc3339(row['last_seen'])}\t"
            f"{row['expires_in']}s\t"
            f"{max_timeout if max_timeout is not None else '-'}s\t"
            f"{max_output if max_output is not None else '-'}\t"
            f"{row['signer']}\t{row['hostname']}\t"
            f"{'verified' if row['verified'] else 'unverified'}"
        )
    return 0


# ---------------------------------------------------------------------------
# Remote state
# ---------------------------------------------------------------------------


class State:
    def __init__(self, path):
        self.path = os.path.abspath(os.path.expanduser(path))
        self.dir = os.path.dirname(self.path)
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        self.lock_path = self.path + ".lock"
        self.results_dir = os.path.join(self.dir, "results")
        self.data = {"requests": {}}

    @contextlib.contextmanager
    def locked(self):
        with open(self.lock_path, "a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            loaded = False
            try:
                self.load()
                loaded = True
                yield self
            finally:
                try:
                    if loaded:
                        self.save()
                finally:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def load(self):
        if not os.path.exists(self.path):
            self.data = {"requests": {}}
            return
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise PipetError(f"cannot read state file {self.path}: {exc}") from exc
        if not isinstance(data, dict):
            raise PipetError(f"state file {self.path} is not a JSON object")
        requests = data.get("requests")
        if not isinstance(requests, dict):
            requests = {}
        self.data = dict(data)
        self.data["requests"] = requests

    def save(self):
        tmp = f"{self.path}.tmp.{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def entry(self, request_id):
        return self.data["requests"].get(request_id)

    def finish(self, request_id, outcome, **fields):
        entry = self.data["requests"].get(request_id) or {}
        entry.update(fields)
        entry["status"] = "done"
        entry["outcome"] = outcome
        entry["finished_at"] = int(time.time())
        self.data["requests"][request_id] = entry

    def prune(self, now):
        requests = self.data["requests"]
        for request_id, entry in list(requests.items()):
            if entry.get("status") != "done":
                continue
            finished = entry.get("finished_at")
            if not isinstance(finished, int):
                finished = now
            if now - finished > STATE_TTL:
                requests.pop(request_id, None)
                self.remove_spool(request_id)

    def spool_path(self, request_id):
        return os.path.join(self.results_dir, request_id + ".json")

    def write_spool(self, request_id, content):
        os.makedirs(self.results_dir, mode=0o700, exist_ok=True)
        path = self.spool_path(request_id)
        tmp = f"{path}.tmp.{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    def read_spool(self, request_id):
        path = self.spool_path(request_id)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read()
        except FileNotFoundError:
            return None

    def remove_spool(self, request_id):
        try:
            os.unlink(self.spool_path(request_id))
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------------
# Execution and results
# ---------------------------------------------------------------------------


def execute_command(command, cwd, timeout, max_output):
    result = {
        "started_at": int(time.time()),
        "finished_at": None,
        "exit_code": None,
        "signal": None,
        "timed_out": False,
        "stdout_b64": "",
        "stderr_b64": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "error": None,
    }
    with tempfile.TemporaryFile() as out_file, tempfile.TemporaryFile() as err_file:
        try:
            proc = subprocess.Popen(
                ["/bin/sh", "-c", command],
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=out_file,
                stderr=err_file,
                start_new_session=True,
            )
        except (OSError, ValueError) as exc:
            result["error"] = str(exc)
            result["finished_at"] = int(time.time())
            return result

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            result["timed_out"] = True
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            proc.wait()

        returncode = proc.returncode
        if returncode is not None and returncode < 0:
            result["signal"] = -returncode
        else:
            result["exit_code"] = returncode

        out_file.seek(0)
        stdout = out_file.read(max_output + 1)
        err_file.seek(0)
        stderr = err_file.read(max_output + 1)
        if len(stdout) > max_output:
            stdout = stdout[:max_output]
            result["stdout_truncated"] = True
        if len(stderr) > max_output:
            stderr = stderr[:max_output]
            result["stderr_truncated"] = True
        result["stdout_b64"] = base64.b64encode(stdout).decode("ascii")
        result["stderr_b64"] = base64.b64encode(stderr).decode("ascii")

    result["finished_at"] = int(time.time())
    return result


def build_result(remote, request_id, request_paste, payload, execution):
    return {
        "v": PROTOCOL_VERSION,
        "kind": "result",
        "remote": remote,
        "request_id": request_id,
        "request_paste": request_paste,
        "signer": payload.get("signer"),
        "started_at": execution.get("started_at"),
        "finished_at": execution.get("finished_at"),
        "exit_code": execution.get("exit_code"),
        "signal": execution.get("signal"),
        "timed_out": execution.get("timed_out", False),
        "truncated": bool(
            execution.get("stdout_truncated") or execution.get("stderr_truncated")
        ),
        "stdout_truncated": execution.get("stdout_truncated", False),
        "stderr_truncated": execution.get("stderr_truncated", False),
        "stdout_b64": execution.get("stdout_b64", ""),
        "stderr_b64": execution.get("stderr_b64", ""),
        "error": execution.get("error"),
    }


def error_result(remote, request_id, request_paste, message, interrupted=False):
    now = int(time.time())
    return {
        "v": PROTOCOL_VERSION,
        "kind": "result",
        "remote": remote,
        "request_id": request_id,
        "request_paste": request_paste,
        "started_at": now,
        "finished_at": now,
        "exit_code": None,
        "signal": None,
        "timed_out": False,
        "truncated": False,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "stdout_b64": "",
        "stderr_b64": "",
        "error": message,
        "interrupted": interrupted,
    }


def shrink_result(result):
    shrunk = dict(result)
    changed = False
    for key, flag in (
        ("stdout_b64", "stdout_truncated"),
        ("stderr_b64", "stderr_truncated"),
    ):
        raw = base64.b64decode(result.get(key) or "")
        if len(raw) > 64 * 1024:
            raw = raw[: max(64 * 1024, len(raw) // 2)]
            shrunk[key] = base64.b64encode(raw).decode("ascii")
            shrunk[flag] = True
            changed = True
    if changed:
        shrunk["truncated"] = True
    return shrunk, changed


def sign_result(result, options):
    if not options.announce_key:
        return result
    unsigned = {key: value for key, value in result.items() if key != "signature"}
    unsigned["signed_by"] = options.announce_signer
    try:
        signature = ssh_sign(
            canonical_bytes(unsigned),
            options.announce_key,
            options.namespace,
        )
    except (PipetError, OSError) as exc:
        log(f"warning: could not sign result for {result.get('request_id')}: {exc}")
        unsigned.pop("signed_by", None)
        return unsigned
    signed = dict(unsigned)
    signed["signature"] = signature
    return signed


def publish_result(cocoon, remote, request_id, result, options=None):
    title = res_title(remote, request_id)
    current = result
    while True:
        if options is not None:
            current = sign_result(current, options)
        content = json.dumps(current, indent=2, sort_keys=True) + "\n"
        try:
            return cocoon.create_paste(content, title)
        except PipetError as exc:
            if exc.status != 413:
                raise
            current, changed = shrink_result(current)
            if not changed:
                raise


# ---------------------------------------------------------------------------
# Remote commands
# ---------------------------------------------------------------------------


def verify_and_parse(cocoon, meta, remote, request_id, options):
    text = cocoon.read_paste(meta["id"])
    payload_bytes, signature = parse_envelope(text)
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PipetError(f"payload is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise PipetError("payload is not a JSON object")

    signer = payload.get("signer")
    if not isinstance(signer, str) or not signer or any(ch.isspace() for ch in signer):
        raise PipetError("payload has an invalid signer identity")

    ssh_verify(
        payload_bytes,
        signature,
        options.allowed_signers,
        signer,
        options.namespace,
    )

    if payload.get("v") != PROTOCOL_VERSION:
        raise PipetError(f"unsupported protocol version {payload.get('v')!r}")
    if payload.get("kind") != "request":
        raise PipetError(f"unexpected payload kind {payload.get('kind')!r}")
    if payload.get("remote") != remote:
        raise PipetError("request is addressed to a different remote")
    if payload.get("request_id") != request_id:
        raise PipetError("request id does not match its title")

    created_at = payload.get("created_at")
    expires_at = payload.get("expires_at")
    now = int(time.time())
    if type(created_at) is not int:
        raise PipetError("request has no valid created_at")
    if created_at > now + CLOCK_LEEWAY:
        raise PipetError("request created_at is too far in the future")
    if type(expires_at) is not int:
        raise PipetError("request has no valid expires_at")
    if now > expires_at + EXPIRY_LEEWAY:
        raise PipetError("request has expired")

    command = payload.get("command")
    if not isinstance(command, str) or not command.strip():
        raise PipetError("request has no command")

    return payload


def process_request(cocoon, remote, request_id, meta, options, state):
    try:
        payload = verify_and_parse(cocoon, meta, remote, request_id, options)
    except TransientError as exc:
        log(f"deferring request {request_id}: {exc}")
        return
    except PipetError as exc:
        log(f"rejecting request {request_id}: {exc}")
        state.finish(request_id, "rejected", reason=str(exc))
        state.save()
        return

    timeout = payload.get("timeout")
    if type(timeout) is not int:
        timeout = options.max_timeout
    timeout = max(1, min(timeout, options.max_timeout))

    requested_max = payload.get("max_output_bytes")
    max_output = options.max_output_bytes
    if type(requested_max) is int:
        max_output = min(max_output, max(1024, requested_max))

    cwd = payload.get("cwd") or options.cwd
    if cwd:
        cwd = os.path.expanduser(cwd)

    state.data["requests"][request_id] = {
        "status": "running",
        "started_at": int(time.time()),
        "request_paste": meta["id"],
        "signer": payload.get("signer"),
    }
    state.save()
    log(
        f"executing request {request_id} from {payload.get('signer')} "
        f"(timeout {timeout}s)"
    )

    execution = execute_command(payload["command"], cwd, timeout, max_output)
    result = build_result(remote, request_id, meta["id"], payload, execution)
    result = sign_result(result, options)
    content = json.dumps(result, indent=2, sort_keys=True) + "\n"
    try:
        state.write_spool(request_id, content)
    except OSError as exc:
        log(f"warning: could not spool result for {request_id}: {exc}")
    try:
        created = publish_result(cocoon, remote, request_id, result, options)
    except TransientError as exc:
        log(f"executed {request_id} but could not publish result yet: {exc}")
        state.data["requests"][request_id] = {
            "status": "executed",
            "started_at": execution.get("started_at"),
            "request_paste": meta["id"],
            "signer": payload.get("signer"),
        }
        state.save()
        return
    except PipetError as exc:
        log(f"executed {request_id} but publishing result failed: {exc}")
        state.finish(
            request_id, "result_failed", reason=str(exc), request_paste=meta["id"]
        )
        state.save()
        return

    state.remove_spool(request_id)
    state.finish(
        request_id,
        "ok",
        request_paste=meta["id"],
        result_paste=created.get("id"),
        exit_code=execution.get("exit_code"),
        timed_out=execution.get("timed_out", False),
    )
    state.save()
    log(f"published result {request_id} as paste {created.get('id')}")


def retry_executed(cocoon, remote, state, options):
    for request_id, entry in list(state.data["requests"].items()):
        if entry.get("status") != "executed":
            continue
        content = state.read_spool(request_id)
        if not content:
            log(f"result spool missing for executed request {request_id}")
            state.finish(request_id, "result_failed", reason="spool missing")
            continue
        try:
            result = json.loads(content)
        except json.JSONDecodeError as exc:
            log(f"result spool for {request_id} is invalid: {exc}")
            state.finish(request_id, "result_failed", reason=f"invalid spool: {exc}")
            continue
        try:
            created = publish_result(cocoon, remote, request_id, result, options)
        except TransientError as exc:
            log(f"will retry result for {request_id}: {exc}")
            continue
        except PipetError as exc:
            log(f"dropping result for {request_id}: {exc}")
            state.finish(request_id, "result_failed", reason=str(exc))
            continue
        state.remove_spool(request_id)
        state.finish(request_id, "ok", result_paste=created.get("id"))
        log(f"published deferred result {request_id} as paste {created.get('id')}")


def handle_interrupted(cocoon, remote, request_id, meta, options, state):
    log(f"request {request_id} was running when the remote stopped; not re-executing")
    result = error_result(
        remote,
        request_id,
        meta.get("id"),
        "remote restarted while executing the command; it was not re-executed",
        interrupted=True,
    )
    result = sign_result(result, options)
    try:
        created = publish_result(cocoon, remote, request_id, result, options)
    except PipetError as exc:
        log(f"could not publish interrupted result for {request_id}: {exc}")
        state.finish(request_id, "result_failed", reason=str(exc))
        return
    state.finish(
        request_id,
        "interrupted",
        request_paste=meta.get("id"),
        result_paste=created.get("id"),
    )


def maybe_announce(cocoon, options, state):
    if not options.announce_key:
        return
    now = int(time.time())
    last = state.data.get("last_announce")
    if type(last) is int and now - last < options.announce_interval:
        return

    payload = {
        "v": PROTOCOL_VERSION,
        "kind": "presence",
        "remote": options.remote,
        "signer": options.announce_signer,
        "created_at": now,
        "expires_at": now + options.announce_ttl,
        "interval": options.announce_interval,
        "max_timeout": options.max_timeout,
        "max_output_bytes": options.max_output_bytes,
        "poll_interval": options.interval,
        "cwd": options.cwd,
        "hostname": socket.gethostname(),
        "version": USER_AGENT,
    }
    try:
        payload_bytes = canonical_bytes(payload)
        signature = ssh_sign(payload_bytes, options.announce_key, options.namespace)
        envelope = make_envelope(payload_bytes, signature)
        created = cocoon.create_paste(envelope, presence_title(options.remote))
    except (PipetError, OSError) as exc:
        log(f"announcement failed: {exc}")
        return
    state.data["last_announce"] = now
    state.save()
    log(
        f"announced presence as paste {created.get('id')} (ttl {options.announce_ttl}s)"
    )


def poll_once(cocoon, remote, options, state):
    now = int(time.time())
    state.prune(now)
    maybe_announce(cocoon, options, state)

    request_infix = f"pipet:{remote}:req:"
    result_infix = f"pipet:{remote}:res:"
    requests = []
    result_pastes = {}

    for meta in cocoon.iter_pastes(remote_query(remote), max_pages=options.max_pages):
        title = meta.get("title") or ""
        if title.startswith(request_infix):
            request_id = title[len(request_infix) :]
            if _REQUEST_ID_RE.match(request_id):
                requests.append((request_id, meta))
        elif title.startswith(result_infix):
            request_id = title[len(result_infix) :]
            if _REQUEST_ID_RE.match(request_id):
                result_pastes[request_id] = meta

    requests.sort(key=lambda item: (item[1].get("created_at") or "", item[0]))
    log(
        f"poll: {len(requests)} request(s), {len(result_pastes)} result(s)",
        verbose_only=True,
        verbose=options.verbose,
    )

    retry_executed(cocoon, remote, state, options)

    for request_id, meta in requests:
        entry = state.entry(request_id)
        if entry and entry.get("status") == "done":
            continue
        if entry and entry.get("status") == "executed":
            continue
        if entry and entry.get("status") == "running":
            if request_id in result_pastes:
                state.finish(
                    request_id,
                    "ok",
                    result_paste=result_pastes[request_id]["id"],
                )
                state.save()
                continue
            if options.retry_interrupted:
                log(f"re-executing interrupted request {request_id}")
                state.data["requests"].pop(request_id, None)
            else:
                handle_interrupted(cocoon, remote, request_id, meta, options, state)
                state.save()
                continue
        process_request(cocoon, remote, request_id, meta, options, state)


class RemoteOptions:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def build_remote_options(args):
    config = load_config(args.config)
    remote = check_remote(opt(args, config, "remote", section="remote") or "")
    announce_key = opt(
        args,
        config,
        "announce_key",
        os.environ.get("PIPET_ANNOUNCE_KEY"),
        section="remote",
    )
    if opt(args, config, "no_announce", False, section="remote"):
        announce_key = None
    if announce_key:
        announce_key = os.path.expanduser(str(announce_key))
    announce_signer = str(
        opt(
            args,
            config,
            "announce_signer",
            os.environ.get("PIPET_ANNOUNCE_SIGNER", remote),
            section="remote",
        )
    )
    announce_interval = int(
        opt(
            args,
            config,
            "announce_interval",
            DEFAULT_ANNOUNCE_INTERVAL,
            section="remote",
        )
    )
    announce_ttl = int(
        opt(args, config, "announce_ttl", DEFAULT_ANNOUNCE_TTL, section="remote")
    )
    announce_interval = max(announce_interval, 1)
    announce_ttl = max(announce_ttl, announce_interval * 2)
    if not announce_signer or any(ch.isspace() for ch in announce_signer):
        raise PipetError(
            "announce signer must be a non-empty string without whitespace"
        )

    options = RemoteOptions(
        remote=remote,
        paste_url=opt(
            args,
            config,
            "paste_url",
            os.environ.get("PIPET_PASTE_URL", DEFAULT_PASTE_URL),
        ),
        namespace=opt(
            args,
            config,
            "namespace",
            os.environ.get("PIPET_NAMESPACE", DEFAULT_NAMESPACE),
        ),
        allowed_signers=os.path.expanduser(
            str(
                opt(
                    args,
                    config,
                    "allowed_signers",
                    DEFAULT_ALLOWED_SIGNERS,
                    section="remote",
                )
            )
        ),
        state_file=os.path.expanduser(
            str(
                opt(
                    args,
                    config,
                    "state_file",
                    state_path_default(),
                    section="remote",
                )
            )
        ),
        cwd=opt(args, config, "cwd", None, section="remote"),
        interval=float(
            opt(args, config, "interval", DEFAULT_INTERVAL, section="remote")
        ),
        max_timeout=int(
            opt(args, config, "max_timeout", DEFAULT_MAX_TIMEOUT, section="remote")
        ),
        max_output_bytes=int(
            opt(
                args,
                config,
                "max_output_bytes",
                DEFAULT_MAX_OUTPUT,
                section="remote",
            )
        ),
        max_pages=int(opt(args, config, "max_pages", DEFAULT_MAX_PAGES)),
        http_timeout=float(opt(args, config, "http_timeout", DEFAULT_HTTP_TIMEOUT)),
        http_client=opt(
            args,
            config,
            "http_client",
            os.environ.get("PIPET_HTTP_CLIENT", "requests"),
            section="remote",
        ),
        retry_interrupted=bool(
            opt(args, config, "retry_interrupted", False, section="remote")
        ),
        verbose=bool(opt(args, config, "verbose", False, section="remote")),
        announce_key=announce_key,
        announce_signer=announce_signer,
        announce_interval=announce_interval,
        announce_ttl=announce_ttl,
    )
    options.max_timeout = max(options.max_timeout, 1)
    options.max_output_bytes = max(options.max_output_bytes, 1024)
    options.max_pages = max(options.max_pages, 1)
    return options


def cmd_remote(args, once):
    options = build_remote_options(args)
    if not os.path.exists(options.allowed_signers):
        raise PipetError(f"allowed_signers file not found: {options.allowed_signers}")
    if options.announce_key and not os.path.exists(options.announce_key):
        raise PipetError(f"announcement key not found: {options.announce_key}")
    cocoon = Cocoon(
        options.paste_url,
        http_timeout=options.http_timeout,
        http_client=options.http_client,
    )
    state = State(options.state_file)

    log(
        f"remote '{options.remote}' polling {cocoon.base} "
        f"(http client: {cocoon.http_client}; "
        f"allowed signers: {options.allowed_signers})"
    )
    while True:
        try:
            with state.locked():
                poll_once(cocoon, options.remote, options, state)
        except TransientError as exc:
            log(f"poll failed, will retry: {exc}")
        except PipetError as exc:
            log(f"error: {exc}")
            if once:
                raise
        if once:
            return 0
        try:
            time.sleep(max(0.2, options.interval))
        except KeyboardInterrupt:
            log("stopping")
            return 0


# ---------------------------------------------------------------------------
# Key helper
# ---------------------------------------------------------------------------


def cmd_pubkey(args):
    config = load_config(args.config)
    key = os.path.expanduser(
        str(opt(args, config, "key", DEFAULT_KEY, section="agent"))
    )
    signer = opt(
        args,
        config,
        "signer",
        os.environ.get("PIPET_SIGNER", getpass.getuser()),
        section="agent",
    )
    if not signer or any(ch.isspace() for ch in signer):
        raise PipetError("signer must be a non-empty string without whitespace")
    candidates = [key]
    if not key.endswith(".pub"):
        candidates.insert(0, key + ".pub")
    for path in candidates:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                public_key = handle.read().strip()
            if public_key:
                print(f"{signer} {public_key}")
                return 0
    raise PipetError(
        f"public key not found for {key} (looked for {', '.join(candidates)})"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def add_common(parser):
    parser.add_argument(
        "--config",
        default=os.environ.get("PIPET_CONFIG"),
        help="JSON config file (default: $PIPET_CONFIG)",
    )
    parser.add_argument(
        "--paste-url",
        help=f"cocoon base URL (default: $PIPET_PASTE_URL or {DEFAULT_PASTE_URL})",
    )
    parser.add_argument(
        "--namespace",
        help=f"SSH signature namespace (default: {DEFAULT_NAMESPACE})",
    )
    parser.add_argument(
        "--http-client",
        choices=HTTP_CLIENTS,
        help=(
            "HTTP transport; auto prefers curl when available "
            "(default: $PIPET_HTTP_CLIENT or requests)"
        ),
    )


def add_announce_args(parser):
    parser.add_argument(
        "--announce-key",
        help=(
            "SSH key used to sign presence announcements; enables discovery "
            "(default: $PIPET_ANNOUNCE_KEY)"
        ),
    )
    parser.add_argument(
        "--announce-signer",
        help="announcement principal (default: the remote name)",
    )
    parser.add_argument(
        "--announce-interval",
        type=int,
        help=f"seconds between announcements (default: {DEFAULT_ANNOUNCE_INTERVAL})",
    )
    parser.add_argument(
        "--announce-ttl",
        type=int,
        help=f"announcement validity in seconds (default: {DEFAULT_ANNOUNCE_TTL})",
    )
    parser.add_argument(
        "--no-announce",
        action="store_true",
        default=None,
        help="do not announce even if a key is configured",
    )


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pipet",
        description=(
            "Signed remote command execution over a cocoon pastebin. "
            "Run 'pipet submit' on the agent side and 'pipet serve' on the remote. "
            "Use 'pipet remotes' to discover announced remotes."
        ),
    )
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    submit = subparsers.add_parser("submit", help="sign and publish a command request")
    add_common(submit)
    submit.add_argument("--remote", help="remote name to address")
    submit.add_argument(
        "-c", "--command", required=True, help="shell command ('-' reads stdin)"
    )
    submit.add_argument("--cwd", help="working directory on the remote")
    submit.add_argument(
        "--timeout",
        type=int,
        help=(
            f"execution timeout in seconds (default: {DEFAULT_TIMEOUT}); "
            "clamped to the remote's max_timeout"
        ),
    )
    submit.add_argument(
        "--expires",
        type=int,
        help=f"request lifetime in seconds (default: {DEFAULT_EXPIRES})",
    )
    submit.add_argument("--key", help=f"SSH private key path (default: {DEFAULT_KEY})")
    submit.add_argument(
        "--signer", help="signer principal in allowed_signers (default: $USER)"
    )
    submit.add_argument(
        "--request-id", help="reuse a specific request id (16-64 hex chars)"
    )
    submit.add_argument(
        "--max-output-bytes", type=int, help="requested output cap per stream"
    )
    submit.add_argument("--json", action="store_true", default=None)
    submit.set_defaults(func=cmd_submit)

    result = subparsers.add_parser("result", help="fetch and print a command result")
    add_common(result)
    result.add_argument("request_id")
    result.add_argument("--remote", help="remote name")
    result.add_argument(
        "--wait", action="store_true", default=None, help="wait for the result"
    )
    result.add_argument(
        "--wait-timeout", type=int, help="seconds to wait (default: 300)"
    )
    result.add_argument(
        "--interval", type=float, help=f"poll interval (default: {DEFAULT_INTERVAL})"
    )
    result.add_argument(
        "--allowed-signers",
        help=(f"trusted remote signers file (default: {DEFAULT_REMOTE_SIGNERS})"),
    )
    result.add_argument(
        "--no-verify",
        action="store_true",
        default=None,
        help="accept unsigned results (unsafe)",
    )
    result.add_argument("--json", action="store_true", default=None)
    result.add_argument("-v", "--verbose", action="store_true", default=None)
    result.set_defaults(func=cmd_result)

    remotes = subparsers.add_parser(
        "remotes",
        aliases=["discover"],
        help="discover remotes that have announced themselves",
    )
    add_common(remotes)
    remotes.add_argument(
        "--allowed-signers",
        help=(f"trusted remote signers file (default: {DEFAULT_REMOTE_SIGNERS})"),
    )
    remotes.add_argument(
        "--ttl",
        type=int,
        help=f"only consider announcements newer than this (default: {DEFAULT_ANNOUNCE_TTL}s)",
    )
    remotes.add_argument("--max-pages", type=int, help="listing pages to scan")
    remotes.add_argument(
        "--no-verify",
        action="store_true",
        default=None,
        help="list announcements without verifying signatures (unsafe)",
    )
    remotes.add_argument("--json", action="store_true", default=None)
    remotes.add_argument("-v", "--verbose", action="store_true", default=None)
    remotes.set_defaults(func=cmd_remotes)

    serve = subparsers.add_parser(
        "serve", help="poll for requests and execute them (long-running)"
    )
    add_common(serve)
    serve.add_argument("--remote", help="this remote's name")
    serve.add_argument(
        "--allowed-signers",
        help=f"ssh-keygen allowed_signers file (default: {DEFAULT_ALLOWED_SIGNERS})",
    )
    serve.add_argument(
        "--state-file",
        help="processed-request state file (default: $XDG_STATE_HOME/pipet/state.json)",
    )
    serve.add_argument("--cwd", help="default working directory")
    serve.add_argument(
        "--interval", type=float, help=f"poll interval (default: {DEFAULT_INTERVAL})"
    )
    serve.add_argument(
        "--max-timeout",
        type=int,
        help=f"maximum execution timeout (default: {DEFAULT_MAX_TIMEOUT})",
    )
    serve.add_argument(
        "--max-output-bytes",
        type=int,
        help=f"output cap per stream (default: {DEFAULT_MAX_OUTPUT})",
    )
    serve.add_argument("--max-pages", type=int, help="listing pages per poll")
    serve.add_argument("--http-timeout", type=float, help="HTTP timeout in seconds")
    serve.add_argument(
        "--retry-interrupted",
        action="store_true",
        default=None,
        help="re-run requests left running by a crash (at-most-once is the default)",
    )
    serve.add_argument("-v", "--verbose", action="store_true", default=None)
    add_announce_args(serve)
    serve.set_defaults(func=lambda args: cmd_remote(args, once=False))

    once = subparsers.add_parser("once", help="run a single request/result poll cycle")
    add_common(once)
    once.add_argument("--remote", help="this remote's name")
    once.add_argument(
        "--allowed-signers",
        help=f"ssh-keygen allowed_signers file (default: {DEFAULT_ALLOWED_SIGNERS})",
    )
    once.add_argument(
        "--state-file",
        help="processed-request state file (default: $XDG_STATE_HOME/pipet/state.json)",
    )
    once.add_argument("--cwd", help="default working directory")
    once.add_argument("--interval", type=float, help=argparse.SUPPRESS)
    once.add_argument("--max-timeout", type=int)
    once.add_argument("--max-output-bytes", type=int)
    once.add_argument("--max-pages", type=int)
    once.add_argument("--http-timeout", type=float)
    once.add_argument("--retry-interrupted", action="store_true", default=None)
    once.add_argument("-v", "--verbose", action="store_true", default=None)
    add_announce_args(once)
    once.set_defaults(func=lambda args: cmd_remote(args, once=True))

    pubkey = subparsers.add_parser(
        "pubkey", help="print an allowed_signers line for this key"
    )
    add_common(pubkey)
    pubkey.add_argument("--key", help=f"SSH key path (default: {DEFAULT_KEY})")
    pubkey.add_argument("--signer", help="principal to put in allowed_signers")
    pubkey.set_defaults(func=cmd_pubkey)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except PipetError as exc:
        eprint(f"pipet: {exc}")
        return 1
    except KeyboardInterrupt:
        eprint("pipet: interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
