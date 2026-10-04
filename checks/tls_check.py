"""Check 2: HTTPS and TLS. Light requests only: connect, read headers."""
import http.client
import re
import socket
import ssl
import warnings
from datetime import datetime, timezone
from finding import Finding

CHECK = "tls"
UA = "SecureCheck/0.2 (consented security check)"
HSTS_MIN = 15552000  # 180 days. Our own rule of thumb, not a standard.
OLD_LIMIT = ("This tests whether this machine's OpenSSL can start an old-protocol "
             "handshake and the server accepts it. A failed attempt does not prove "
             "the server refuses old protocols.")


def _verify_finding(domain, err):
    msg = (getattr(err, "verify_message", "") or str(err)).lower()
    if "expired" in msg:
        title, why = "Certificate has expired", "Browsers show a scary warning and many visitors leave."
        fix = "Renew the certificate now. Turn on auto-renewal (for example Let's Encrypt)."
    elif "hostname" in msg or "doesn't match" in msg or "does not match" in msg:
        title, why = "Certificate does not match the domain", "Browsers warn visitors because the certificate is for a different name."
        fix = "Issue a certificate that includes this exact domain name."
    elif "self-signed" in msg or "self signed" in msg:
        title, why = "Certificate is self-signed", "Browsers do not trust it, and an attacker could swap it unnoticed."
        fix = "Install a certificate from a trusted authority. Let's Encrypt is free."
    else:
        title, why = "Certificate is not trusted", "Browsers may warn visitors or refuse to load the site."
        fix = "Install the full certificate chain from a trusted authority."
    return Finding(CHECK, domain, "High", title, f"Certificate check failed: {msg}",
                   f"verify error: {msg}", why, fix)


def _get_cert(domain, port, cafile, timeout):
    ctx = ssl.create_default_context(cafile=cafile)
    # Some systems (Kali) let the default client use old TLS. Require modern TLS
    # here, so the old-protocol checks below are the only place old TLS is tried.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((domain, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=domain) as s:
            return s.version(), s.getpeercert()


def _get_cert_retry(domain, port, cafile, timeout):
    """Try twice. A slow network should not look like a broken website."""
    for attempt in (1, 2):
        try:
            return _get_cert(domain, port, cafile, timeout)
        except (socket.timeout, socket.gaierror):
            if attempt == 2:
                raise


def _old_ctx(version):
    """Client context for one old protocol, or None if this machine cannot try."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            ctx.minimum_version = version
            ctx.maximum_version = version
            return ctx
    except (ssl.SSLError, ValueError, AttributeError):
        return None


def _accepts(domain, port, version, timeout):
    """True/False if an old-protocol handshake worked. None if we cannot try."""
    ctx = _old_ctx(version)
    if ctx is None:
        return None
    try:
        with socket.create_connection((domain, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain):
                return True
    except (ssl.SSLError, OSError):
        return False


def _hsts(domain, port, timeout):
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        c = http.client.HTTPSConnection(domain, port, timeout=timeout, context=ctx)
        c.request("GET", "/", headers={"User-Agent": UA})
        r = c.getresponse()
        return r.getheader("Strict-Transport-Security"), r.status
    except (OSError, http.client.HTTPException):
        return None, None


def _redirect(domain, port, timeout):
    try:
        c = http.client.HTTPConnection(domain, port, timeout=timeout)
        c.request("GET", "/", headers={"User-Agent": UA})
        r = c.getresponse()
        return r.status, r.getheader("Location", "")
    except (OSError, http.client.HTTPException):
        return None, ""


def check_tls(domain, https_port=443, http_port=80, cafile=None, timeout=8):
    domain = domain.strip().lower().rstrip(".")
    out = []

    # Certificate and HTTPS availability
    try:
        version, cert = _get_cert_retry(domain, https_port, cafile, timeout)
        left = (ssl.cert_time_to_seconds(cert["notAfter"]) -
                datetime.now(timezone.utc).timestamp()) / 86400
        ev = f"protocol {version}; notAfter {cert['notAfter']}; {left:.0f} days left"
        if left <= 14:
            out.append(Finding(CHECK, domain, "Medium", "Certificate expires very soon",
                               f"About {left:.0f} days left.", ev,
                               "If it lapses, visitors see a warning.",
                               "Renew now and turn on auto-renewal."))
        elif left <= 30:
            out.append(Finding(CHECK, domain, "Low", "Certificate expires within 30 days",
                               f"About {left:.0f} days left.", ev,
                               "A missed renewal will cause visitor warnings.",
                               "Check that auto-renewal works."))
        else:
            out.append(Finding(CHECK, domain, "Info", "Certificate is valid",
                               f"Trusted, matches the domain, {left:.0f} days left.", ev,
                               "Visitors can reach the site securely.", "No action needed."))
    except ssl.SSLCertVerificationError as e:
        out.append(_verify_finding(domain, e))
    except (socket.timeout, socket.gaierror) as e:
        return [Finding(CHECK, domain, "Info", "HTTPS check could not complete",
                        "The connection timed out or the domain name did not resolve.",
                        f"{type(e).__name__}: {e}",
                        "We could not tell whether HTTPS works.",
                        "Check the internet connection and run the check again.",
                        "A slow or broken network on our side looks the same. "
                        "This is not a finding about the website.")]
    except (ConnectionRefusedError, OSError, ssl.SSLError) as e:
        if isinstance(e, ssl.SSLError):
            old = [n for n, v in (("TLS 1.0", ssl.TLSVersion.TLSv1),
                                  ("TLS 1.1", ssl.TLSVersion.TLSv1_1))
                   if _accepts(domain, https_port, v, timeout)]
            if old:
                return [Finding(CHECK, domain, "High", "Server only supports old TLS",
                                f"Modern TLS failed, but {' and '.join(old)} worked.",
                                f"{type(e).__name__}: {e}",
                                "Modern browsers may refuse to connect, and old "
                                "protocols have known weaknesses.",
                                "Enable TLS 1.2 and 1.3 and turn off the old versions.",
                                OLD_LIMIT)]
        out.append(Finding(CHECK, domain, "High", "HTTPS not available",
                           "Could not make a secure connection.", f"{type(e).__name__}: {e}",
                           "Anything visitors send can be read on the way.",
                           "Install a certificate and turn on HTTPS.",
                           "A network problem on our side can look the same. Run it again."))
        return out

    # Old protocols
    for name, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        ok = _accepts(domain, https_port, ver, timeout)
        if ok:
            out.append(Finding(CHECK, domain, "Medium", f"{name} is still accepted",
                               f"The server completed a {name} handshake.",
                               f"{name} handshake succeeded",
                               "Old protocols have known weaknesses.",
                               f"Turn off {name}. Allow TLS 1.2 and 1.3 only.", OLD_LIMIT))

    # HSTS
    hsts, status = _hsts(domain, https_port, timeout)
    if status is not None:
        if not hsts:
            out.append(Finding(CHECK, domain, "Medium", "HSTS is not set",
                               "No Strict-Transport-Security header.", f"HTTPS GET / -> {status}, no HSTS",
                               "Browsers are not told to always use HTTPS for this site.",
                               "Add the header: Strict-Transport-Security: max-age=31536000"))
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.I)
            if not m or int(m.group(1)) < HSTS_MIN:
                out.append(Finding(CHECK, domain, "Low", "HSTS time is short",
                                   "max-age is missing or under 180 days.", hsts,
                                   "The protection expires quickly.",
                                   "Set max-age to at least 31536000 (one year)."))

    # HTTP to HTTPS redirect
    code, loc = _redirect(domain, http_port, timeout)
    if code is not None:
        if code in (301, 302, 303, 307, 308) and loc.lower().startswith("https://"):
            pass
        else:
            out.append(Finding(CHECK, domain, "Medium", "HTTP does not redirect to HTTPS",
                               "The plain HTTP site answers without sending visitors to HTTPS.",
                               f"HTTP GET / -> {code} {loc}".strip(),
                               "Visitors who type the plain address stay on an unprotected page.",
                               "Set a permanent redirect from http:// to https://."))
    return out
