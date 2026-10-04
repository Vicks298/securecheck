import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from checks.headers_check import check_headers
from helpers import serve, handler

GOOD = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Server": "Apache",
}


def run(pki, headers=None, routes=None):
    https = serve(handler(200, headers, routes), pki)
    return check_headers("localhost", https.server_port)


def titles(fs):
    return {(f.severity, f.title) for f in fs}


def test_all_good(pki):
    assert titles(run(pki, GOOD)) == {("Info", "Security headers look good")}


def test_nothing_set(pki):
    t = titles(run(pki, {}))
    assert ("Medium", "No Content-Security-Policy") in t
    assert ("Low", "No clickjacking protection") in t
    assert ("Low", "X-Content-Type-Options is not set") in t
    assert ("Low", "No Referrer-Policy") in t


def test_frame_options_counts(pki):
    h = dict(GOOD, **{"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY"})
    assert "No clickjacking protection" not in {f.title for f in run(pki, h)}


def test_version_leaks(pki):
    h = dict(GOOD, **{"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"})
    t = titles(run(pki, h))
    assert ("Low", "Web server version is shown") in t
    assert ("Low", "Technology is shown in headers") in t


def test_unsafe_csp_and_report_only(pki):
    h = dict(GOOD, **{"Content-Security-Policy": "script-src 'self' 'unsafe-inline'; frame-ancestors 'self'"})
    assert ("Low", "CSP allows unsafe scripts") in titles(run(pki, h))
    h = dict(GOOD)
    del h["Content-Security-Policy"]
    h["Content-Security-Policy-Report-Only"] = "default-src 'self'"
    assert ("Low", "CSP is report-only") in titles(run(pki, h))


def test_cookie_flags(pki):
    h = list(GOOD.items()) + [("Set-Cookie", "sid=abc; Path=/"),
                              ("Set-Cookie", "ok=1; Path=/; Secure; HttpOnly; SameSite=Lax")]
    fs = {f.title: f for f in run(pki, h)}
    assert fs["Cookies without the Secure flag"].severity == "Medium"
    for t in ("Cookies without the Secure flag", "Cookies without the HttpOnly flag",
              "Cookies without a SameSite setting"):
        assert fs[t].detail.split(": ")[1] == "sid"


def test_follows_same_site_redirect(pki):
    routes = {"/": (301, {"Location": "/home"}), "/home": (200, GOOD)}
    assert titles(run(pki, routes=routes)) == {("Info", "Security headers look good")}


def test_stops_at_other_site(pki):
    routes = {"/": (301, {"Location": "https://other.example/"})}
    t = titles(run(pki, routes=routes))
    assert ("Medium", "No Content-Security-Policy") in t  # judged the redirect response, did not leave the site


def test_fetch_failure():
    t = titles(check_headers("localhost", 1, timeout=2))
    assert t == {("Info", "Home page could not be fetched")}


def test_evidence_names_final_url(pki):
    routes = {"/": (301, {"Location": "/home"}), "/home": (200, {"Server": "nginx/1.29.8"})}
    fs = run(pki, routes=routes)
    server = next(f for f in fs if f.title == "Web server version is shown")
    assert "/home" in server.evidence and "after 1 redirect" in server.evidence
    assert "nginx/1.29.8" in server.evidence


def test_fix_text_matches_server(pki):
    f = next(x for x in run(pki, dict(GOOD, Server="nginx/1.29.8")) if x.title == "Web server version is shown")
    assert "server_tokens off" in f.fix and "Apache" not in f.fix
    f = next(x for x in run(pki, dict(GOOD, Server="Apache/2.4.41")) if x.title == "Web server version is shown")
    assert "ServerTokens Prod" in f.fix
