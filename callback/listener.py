"""Callback listener for the safe exploit check.

Port 1389: accepts TCP connections (what a Log4Shell lookup does first),
answers an LDAP bind with "success" so the client sends its search request
(which carries the per-check token), records what it received, and closes.
It never returns an LDAP referral or any payload, so nothing is executed.

Port 8000: GET /hits?since=<ts> -> recorded connections, DELETE /hits clears.
"""
import json
import socket
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HITS = []
LOCK = threading.Lock()
# LDAPMessage { messageID 1, bindResponse { resultCode success, matchedDN "", diagnosticMessage "" } }
BIND_SUCCESS = bytes.fromhex("300c02010161070a010004000400")


class LdapHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(3)
        received = b""
        try:
            received += sock.recv(4096)
            if received[:1] == b"\x30":          # looks like LDAP: say "bound"
                sock.sendall(BIND_SUCCESS)
                received += sock.recv(4096)
            else:                                 # anything else: read what is sent
                while len(received) < 65536:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    received += chunk
        except (socket.timeout, OSError):
            pass
        text = "".join(chr(b) if 32 <= b < 127 or b in (10, 13) else "." for b in received)
        with LOCK:
            HITS.append({"ts": time.time(), "peer": self.client_address[0],
                         "bytes": len(received), "data": text[:2000]})
        print(f"[callback] connection from {self.client_address[0]}: {text[:120]!r}", flush=True)


class Api(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/health":
            return self._json(200, {"ok": True})
        if url.path != "/hits":
            return self._json(404, {"error": "not found"})
        since = float(parse_qs(url.query).get("since", ["0"])[0])
        with LOCK:
            return self._json(200, [h for h in HITS if h["ts"] >= since])

    def do_DELETE(self):
        with LOCK:
            HITS.clear()
        self._json(200, {"cleared": True})

    def log_message(self, *args):
        pass


class ThreadingTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    ldap = ThreadingTCP(("0.0.0.0", 1389), LdapHandler)
    threading.Thread(target=ldap.serve_forever, daemon=True).start()
    print("[callback] listening on 1389 (ldap) and 8000 (api)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8000), Api).serve_forever()
