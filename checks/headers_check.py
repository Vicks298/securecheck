"""Check 3: security headers, cookie flags, software disclosure. One home-page GET."""
import http.client
import re
import ssl
from urllib.parse import urlsplit
from finding import Finding

CHECK = "headers"
UA = "SecureCheck/0.3 (consented security check)"
MAX_REDIRECTS = 3
PAGE_LIMIT = "Only the home page was requested. Other pages may send different headers."


def _same_site(host, domain):
    strip = lambda h: h.lower().removeprefix("www.")
    return strip(host) == strip(domain)


def _fetch(domain, port, timeout):
    """GET the home page over HTTPS. Follow redirects only within the same site."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False   # the TLS check judges the certificate, not this one
    ctx.verify_mode = ssl.CERT_NONE
    host, path = domain, "/"
    hops = 0
    for _ in range(MAX_REDIRECTS + 1):
        c = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        c.request("GET", path, headers={"User-Agent": UA})
        r = c.getresponse()
        loc = r.getheader("Location")
        if r.status in (301, 302, 303, 307, 308) and loc:
            u = urlsplit(loc)
            if u.scheme in ("", "https") and (not u.netloc or _same_site(u.hostname or "", domain)):
                host = u.hostname or host
                port = u.port or port
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                c.close()
                hops += 1
                continue
        return r.status, r.msg, host, path, hops
    return r.status, r.msg, host, path, hops


def _directive(csp, name):
    for part in csp.split(";"):
        bits = part.strip().split()
        if bits and bits[0].lower() == name:
            return " ".join(bits[1:]).lower()
    return None


def _cookies(msg):
    found = []
    for raw in msg.get_all("Set-Cookie") or []:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0]
        flags = {p.split("=", 1)[0].lower() for p in parts[1:]}
        found.append((name, flags, raw))
    return found


def check_headers(domain, https_port=443, timeout=8):
    domain = domain.strip().lower().rstrip(".")
    try:
        status, h, host, path, hops = _fetch(domain, https_port, timeout)
    except (OSError, http.client.HTTPException) as e:
        return [Finding(CHECK, domain, "Info", "Home page could not be fetched",
                        "No secure response, so headers were not checked.",
                        f"{type(e).__name__}: {e}", "We could not check headers.",
                        "Fix HTTPS first (see the TLS findings), then run again.")]
    ev = f"HTTPS GET https://{host}{path} -> {status}"
    if hops:
        ev += f" (after {hops} redirect{'s' if hops > 1 else ''})"
    out = []

    def add(sev, title, detail, why, fix, evidence=None):
        shown = ev if evidence is None else f"{ev} | {evidence}"
        out.append(Finding(CHECK, domain, sev, title, detail, shown, why, fix, PAGE_LIMIT))

    csp = h.get("Content-Security-Policy")
    if not csp:
        if h.get("Content-Security-Policy-Report-Only"):
            add("Low", "CSP is report-only", "The policy only reports problems. It blocks nothing.",
                "Injected scripts are not stopped.", "After reviewing the reports, enforce it with Content-Security-Policy.")
        else:
            add("Medium", "No Content-Security-Policy", "The Content-Security-Policy header is missing.",
                "If an attacker injects a script into a page, the browser has no rule to stop it.",
                "Add a Content-Security-Policy header. Start with Content-Security-Policy-Report-Only, "
                "review what it would block, then enforce it.")
    else:
        scripts = _directive(csp, "script-src") or _directive(csp, "default-src") or ""
        risky = [k for k in ("'unsafe-inline'", "'unsafe-eval'") if k in scripts]
        if risky and "nonce-" not in scripts and "sha256-" not in scripts:
            add("Low", "CSP allows unsafe scripts", f"The script rule includes {', '.join(risky)}.",
                "This weakens the protection a policy gives.", "Remove the unsafe keywords. Use nonces or hashes for inline scripts.",
                evidence=f"CSP: {csp[:200]}")

    if not h.get("X-Frame-Options") and not (csp and _directive(csp, "frame-ancestors") is not None):
        add("Low", "No clickjacking protection", "Neither X-Frame-Options nor frame-ancestors is set.",
            "Another site could show your page inside a hidden frame and trick visitors into clicking.",
            "Add: Content-Security-Policy: frame-ancestors 'self'  (or X-Frame-Options: SAMEORIGIN).")

    if (h.get("X-Content-Type-Options") or "").strip().lower() != "nosniff":
        add("Low", "X-Content-Type-Options is not set", "The header is missing or not 'nosniff'.",
            "Browsers may guess a file's type and run something that was not meant to run.",
            "Add: X-Content-Type-Options: nosniff")

    if not h.get("Referrer-Policy"):
        add("Low", "No Referrer-Policy", "The Referrer-Policy header is missing.",
            "Full page addresses may be sent to other sites when visitors click links.",
            "Add: Referrer-Policy: strict-origin-when-cross-origin")

    server = h.get("Server", "")
    if re.search(r"\d+\.\d+", server):
        add("Low", "Web server version is shown", f"The Server header shows: {server}",
            "Attackers can look up known weaknesses for that exact version.",
            ("Hide the version: add  server_tokens off;  to your nginx settings." if "nginx" in server.lower()
             else "Hide the version: set  ServerTokens Prod  in your Apache settings." if "apache" in server.lower()
             else "Hide the version in your web server settings."), evidence=f"Server: {server}")
    powered = h.get("X-Powered-By")
    if powered:
        add("Low", "Technology is shown in headers", f"X-Powered-By shows: {powered}",
            "It tells attackers which software to target.",
            "Remove the X-Powered-By header in your server or app settings.", evidence=f"X-Powered-By: {powered}")

    cookies = _cookies(h)
    for flag, sev, title, why, fix in (
        ("secure", "Medium", "Cookies without the Secure flag",
         "A cookie without Secure can be sent over plain HTTP, where it can be read.",
         "Add the Secure flag when the cookie is set."),
        ("httponly", "Low", "Cookies without the HttpOnly flag",
         "Scripts on the page can read the cookie. This matters most for login cookies.",
         "Add HttpOnly to cookies that scripts do not need."),
        ("samesite", "Low", "Cookies without a SameSite setting",
         "Other sites may be able to trigger actions using the visitor's cookie.",
         "Add SameSite=Lax (or Strict) when the cookie is set."),
    ):
        names = [n for n, f, _ in cookies if flag not in f]
        if names:
            add(sev, title, f"Cookies missing it: {', '.join(names)}", why, fix,
                evidence="; ".join(r[:80] for n, f, r in cookies if flag not in f))

    if not out:
        out.append(Finding(CHECK, domain, "Info", "Security headers look good",
                           "The common headers are set and no cookie problems were seen.",
                           ev, "Browsers are told to apply extra protection.", "No action needed.", PAGE_LIMIT))
    return out
