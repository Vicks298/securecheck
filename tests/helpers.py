import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # clients that quit mid-handshake are expected in these tests


def serve(handler_cls, pki=None, cert="srv.pem", old_only=None):
    srv = QuietServer(("127.0.0.1", 0), handler_cls)
    if pki:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if old_only is None:
            # Pin the test server to modern TLS. Some systems (Kali) allow
            # old protocols by default, which would hide the real result.
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            ctx.minimum_version = old_only
            if old_only is not ssl.TLSVersion.MINIMUM_SUPPORTED:
                ctx.maximum_version = old_only
        ctx.load_cert_chain(pki / cert, pki / "srv.key")
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def handler(status=200, headers=None, routes=None):
    """headers: dict or list of (name, value) pairs. routes: {path: (status, headers[, body])}."""
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            got = (routes or {}).get(self.path, (status, headers))
            st, hd = got[0], got[1]
            body = got[2] if len(got) > 2 else b""
            items = list(hd.items() if isinstance(hd, dict) else (hd or []))
            # Python adds its own Server header ("BaseHTTP/0.6 Python/..."). Replace it,
            # so tests control exactly what the server announces.
            self._server = next((v for k, v in items if k.lower() == "server"), "Apache")
            self.send_response(st)
            for k, v in items:
                if k.lower() != "server":
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def version_string(self):
            return self._server

        def log_message(self, *a):
            pass
    return H
