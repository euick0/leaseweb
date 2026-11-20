"""Billing service of the demo shop. Public, behind its gateway.

Signs invoices with the key named in the X-Key-Id header, loaded through
acme-authutils (path traversal in 1.0.0), and formats them with acme-textfmt.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import acme_authutils
import acme_textfmt


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            try:
                acme_textfmt.banner("health")
            except Exception as exc:
                return self._send(500, f"unhealthy: {exc}\n")
            return self._send(200, "ok\n")
        if self.path.startswith("/invoice"):
            key_id = self.headers.get("X-Key-Id", "default")
            try:
                key = acme_authutils.load_key(key_id)
            except (OSError, ValueError):
                return self._send(400, f"unknown signing key {key_id!r}\n")
            body = (acme_textfmt.banner("Invoice #1001") + "\namount: 120.00 EUR\n"
                    f"signed with key {key_id} (fingerprint {acme_authutils.fingerprint(key)})\n")
            return self._send(200, body)
        return self._send(200, "billing\n")

    def _send(self, status, body):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print(f"billing {self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"billing listening on {port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
