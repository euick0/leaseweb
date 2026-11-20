"""Meridian Freight customer portal. Public, behind its gateway.

Authenticates customers and hands back a session token minted by
meridian-auth (session forgery in 1.0.0). The account page trusts whatever
role the session claims, so a forged admin session unlocks the admin console.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import meridian_auth

# Demo customers. Any of these can sign in; the portal is a stand-in, so the
# password check is deliberately trivial -- the vulnerability under test is the
# session token, not the password store.
USERS = {"ada": "freight", "grace": "freight"}

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Meridian Freight &middot; Customer Portal</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 16px/1.5 system-ui, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }}
  .bar {{ background: #1e293b; padding: 14px 24px; font-weight: 700; letter-spacing: .02em; }}
  .bar span {{ color: #38bdf8; }}
  .wrap {{ max-width: 420px; margin: 8vh auto; padding: 0 16px; }}
  .card {{ background: #1e293b; border-radius: 12px; padding: 28px; box-shadow: 0 10px 30px #0006; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  p.sub {{ margin: 0 0 20px; color: #94a3b8; font-size: 14px; }}
  label {{ display: block; font-size: 13px; color: #94a3b8; margin: 14px 0 4px; }}
  input {{ width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 8px;
           border: 1px solid #334155; background: #0f172a; color: #e2e8f0; }}
  button {{ margin-top: 20px; width: 100%; padding: 11px; border: 0; border-radius: 8px;
            background: #38bdf8; color: #06283d; font-weight: 700; font-size: 15px; cursor: pointer; }}
  .msg {{ margin-top: 14px; font-size: 14px; color: #fca5a5; }}
  .acct {{ line-height: 1.8; }}
  .admin {{ margin-top: 16px; padding: 12px 14px; border-radius: 8px;
            background: #7f1d1d; color: #fecaca; font-size: 14px; }}
  a {{ color: #38bdf8; }}
</style></head>
<body>
  <div class="bar">MERIDIAN <span>FREIGHT</span></div>
  <div class="wrap"><div class="card">{body}</div></div>
</body></html>"""

LOGIN_BODY = """<h1>Customer sign in</h1>
<p class="sub">Track shipments and manage your Meridian account.</p>
<form method="post" action="/login">
  <label for="u">Username</label>
  <input id="u" name="username" autocomplete="username" value="ada">
  <label for="p">Password</label>
  <input id="p" name="password" type="password" autocomplete="current-password" value="freight">
  <button type="submit">Sign in</button>
</form>{msg}"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            return self._send(200, "ok\n", "text/plain; charset=utf-8")
        if self.path in ("/", "/login"):
            return self._html(200, LOGIN_BODY.format(msg=""))
        if self.path == "/account":
            return self._account()
        return self._send(404, "not found\n", "text/plain; charset=utf-8")

    def do_POST(self):
        if self.path != "/login":
            return self._send(404, "not found\n", "text/plain; charset=utf-8")
        length = int(self.headers.get("Content-Length", "0") or "0")
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        user = (form.get("username", [""])[0]).strip()
        password = (form.get("password", [""])[0])
        if USERS.get(user) != password:
            return self._html(401, LOGIN_BODY.format(
                msg='<p class="msg">Incorrect username or password.</p>'))
        token = meridian_auth.issue_session({"user": user, "role": "customer"})
        self.send_response(303)
        self.send_header("Location", "/account")
        self.send_header("Set-Cookie", f"session={token}; HttpOnly; Path=/")
        self.end_headers()

    def _account(self):
        token = self._cookie("session")
        if not token:
            return self._html(401, '<h1>Not signed in</h1><p class="sub">'
                                    '<a href="/login">Sign in</a> to view your account.</p>')
        try:
            claims = meridian_auth.verify_session(token)
        except Exception:
            return self._html(401, '<h1>Session invalid</h1><p class="sub">'
                                    'Please <a href="/login">sign in</a> again.</p>')
        user = claims.get("user", "customer")
        role = claims.get("role", "customer")
        admin = ('<div class="admin"><b>Admin console</b><br>'
                 'Billing exports, customer records and fleet routing are unlocked.</div>'
                 if role == "admin" else "")
        return self._html(200, f'<h1>Welcome, {user}</h1>'
                               f'<p class="sub">Signed in as <b>{role}</b>.</p>'
                               f'<div class="acct">Next shipment: <b>MF-10293</b> &middot; in transit<br>'
                               f'Account balance: <b>&euro;0.00</b></div>{admin}')

    # ------------------------------------------------------------- helpers
    def _cookie(self, name):
        for part in (self.headers.get("Cookie", "") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def _html(self, status, body):
        return self._send(status, PAGE.format(body=body), "text/html; charset=utf-8")

    def _send(self, status, body, ctype):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print(f"meridian {self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"meridian portal listening on {port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
