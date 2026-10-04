import os, ssl, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from checks.tls_check import check_tls, _old_ctx
from helpers import serve, handler


def titles(findings):
    return {(f.severity, f.title) for f in findings}


def test_good_setup(pki):
    https = serve(handler(200, {"Strict-Transport-Security": "max-age=31536000"}), pki)
    http = serve(handler(301, {"Location": "https://localhost/"}))
    t = titles(check_tls("localhost", https.server_port, http.server_port, str(pki / "ca.pem")))
    assert t == {("Info", "Certificate is valid")}, t


def test_untrusted_cert(pki):
    https = serve(handler(200, {"Strict-Transport-Security": "max-age=31536000"}), pki)
    t = titles(check_tls("localhost", https.server_port, 1))
    assert any(sev == "High" and "Certificate" in title for sev, title in t), t


def test_no_hsts_and_no_redirect(pki):
    https = serve(handler(200), pki)
    http = serve(handler(200))
    t = titles(check_tls("localhost", https.server_port, http.server_port, str(pki / "ca.pem")))
    assert ("Medium", "HSTS is not set") in t
    assert ("Medium", "HTTP does not redirect to HTTPS") in t


def test_https_closed():
    t = titles(check_tls("localhost", 1, 1, timeout=2))
    assert t == {("High", "HTTPS not available")}


def test_cert_expiring_soon(pki):
    https = serve(handler(200, {"Strict-Transport-Security": "max-age=31536000"}), pki, "short.pem")
    t = titles(check_tls("localhost", https.server_port, 1, str(pki / "ca.pem")))
    assert ("Medium", "Certificate expires very soon") in t


def test_old_tls_only_is_flagged(pki, monkeypatch):
    # Kali's Python lets a default client negotiate TLS 1.0. Copy that here.
    real = ssl.create_default_context

    def kali_like(*a, **k):
        ctx = real(*a, **k)
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        return ctx

    monkeypatch.setattr(ssl, "create_default_context", kali_like)
    if _old_ctx(ssl.TLSVersion.TLSv1) is None:
        pytest.skip("this machine's OpenSSL cannot attempt TLS 1.0")
    try:
        https = serve(handler(200), pki, old_only=ssl.TLSVersion.TLSv1)
    except (ssl.SSLError, ValueError):
        pytest.skip("this machine's OpenSSL cannot serve TLS 1.0")
    t = titles(check_tls("localhost", https.server_port, 1, str(pki / "ca.pem")))
    assert ("High", "Server only supports old TLS") in t, t


def test_old_tls_still_accepted(pki):
    if _old_ctx(ssl.TLSVersion.TLSv1) is None:
        pytest.skip("this machine's OpenSSL cannot attempt TLS 1.0")
    try:
        https = serve(handler(200), pki, old_only=ssl.TLSVersion.MINIMUM_SUPPORTED)
    except (ssl.SSLError, ValueError):
        pytest.skip("this machine's OpenSSL cannot serve TLS 1.0")
    t = titles(check_tls("localhost", https.server_port, 1, str(pki / "ca.pem")))
    assert ("Medium", "TLS 1.0 is still accepted") in t, t


def test_timeout_is_not_a_finding(monkeypatch):
    import socket
    from checks import tls_check
    calls = []

    def slow(*a, **k):
        calls.append(1)
        raise socket.timeout("handshake timed out")

    monkeypatch.setattr(tls_check, "_get_cert", slow)
    t = titles(check_tls("example.test"))
    assert t == {("Info", "HTTPS check could not complete")}
    assert len(calls) == 2  # tried twice before giving up
