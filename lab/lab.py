"""A fake small-business website for testing SecureCheck.
   python3 lab/lab.py weak    -> the shop before any fixes
   python3 lab/lab.py fixed   -> the same shop after the fixes
Not a real business. Everything it serves is made up."""
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
HTTPS_PORT, HTTP_PORT = 8443, 8080
PAGE = b"<html><body><h1>Demo Shop</h1><p>A made-up business for testing SecureCheck.</p></body></html>"
FAKE_ENV = b"DB_HOST=localhost\nDB_PASSWORD=demo-not-a-real-password\nAPI_KEY=demo-not-a-real-key\n"
FIXED_HEADERS = [
    ("Strict-Transport-Security", "max-age=31536000"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Set-Cookie", "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"),
]


class Quiet(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass


def make_handler(mode, secure):
    class H(BaseHTTPRequestHandler):
        def version_string(self):
            return "nginx/1.18.0" if mode == "weak" else "nginx"

        def log_message(self, *a):
            pass

        def reply(self, status, headers, body):
            self.send_response(status)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if not secure and mode == "fixed":
                return self.reply(301, [("Location", f"https://demo-shop.test:{HTTPS_PORT}/")], b"")
            if self.path == "/.env":
                if mode == "weak":
                    return self.reply(200, [("Content-Type", "text/plain")], FAKE_ENV)
                return self.reply(404, [("Content-Type", "text/plain")], b"not found")
            if self.path != "/":
                return self.reply(404, [("Content-Type", "text/plain")], b"not found")
            headers = [("Content-Type", "text/html")]
            if mode == "weak":
                headers.append(("Set-Cookie", "session=abc123; Path=/"))
            elif secure:
                headers += FIXED_HEADERS
            self.reply(200, headers, PAGE)
    return H


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("weak", "fixed"):
        sys.exit("usage: python3 lab/lab.py weak|fixed")
    mode = sys.argv[1]
    pki = os.path.join(HERE, "pki")
    if not os.path.exists(os.path.join(pki, "server.pem")):
        sys.exit("Run lab/make_certs.sh first.")
    https = Quiet(("127.0.0.1", HTTPS_PORT), make_handler(mode, True))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(os.path.join(pki, "server.pem"), os.path.join(pki, "server.key"))
    https.socket = ctx.wrap_socket(https.socket, server_side=True)
    http = Quiet(("127.0.0.1", HTTP_PORT), make_handler(mode, False))
    threading.Thread(target=http.serve_forever, daemon=True).start()
    print(f"Demo shop ({mode}) is running: https port {HTTPS_PORT}, http port {HTTP_PORT}. Ctrl+C to stop.")
    try:
        https.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
