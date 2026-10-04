"""Check 5: exposed files. One GET per path. Contents are never stored."""
import http.client
import re
import ssl
from finding import Finding

CHECK = "paths"
UA = "SecureCheck/0.6 (consented security check)"
LIMIT = ("Only a few common file addresses were requested, one time each. A clean result does "
         "not mean nothing is exposed. Contents are read briefly to confirm and are not stored.")
KEEP_FIX = ("Remove it from the public folder or block it in your web server settings. ")


def _html(ct):
    return "html" in ct


def _git(status, ct, body):
    return "file starts with 'ref:'" if status == 200 and body.startswith(b"ref:") else None


def _env(status, ct, body):
    ok = status == 200 and not _html(ct) and re.search(rb"^[A-Za-z_][A-Za-z0-9_]*=", body, re.M)
    return "readable file with KEY=value lines" if ok else None


def _zip(status, ct, body):
    return "file starts with the zip signature" if status == 200 and body.startswith(b"PK\x03\x04") else None


def _sql(status, ct, body):
    ok = status == 200 and not _html(ct) and (b"CREATE TABLE" in body or b"INSERT INTO" in body)
    return "file contains SQL statements" if ok else None


def _pma(status, ct, body):
    return "page identifies itself as phpMyAdmin" if status == 200 and b"phpmyadmin" in body.lower() else None


def _wp(status, ct, body):
    ok = status == 200 and (b"user_login" in body or b"wp-submit" in body)
    return "WordPress login form found" if ok else None


# path: (detector, severity, title, why, fix)
PATHS = {
    "/.git/HEAD": (_git, "Critical", "Git repository is public",
                   "Anyone can download the site's source code and its history, which may hold passwords.",
                   "Block access to /.git and remove the folder from the live site. Change any password or key ever stored in the code."),
    "/.env": (_env, "Critical", "Settings file with secrets is public",
              "This file usually holds passwords and keys. Anyone can read them.",
              KEEP_FIX + "Change every password and key it held. Treat them as stolen."),
    "/backup.sql": (_sql, "Critical", "Database backup is public",
                    "Anyone can download the database, which may hold customer data.",
                    KEEP_FIX + "If it holds customer data, treat this as a data breach and get advice."),
    "/backup.zip": (_zip, "High", "Backup file is public",
                    "Backups often hold source code, passwords or data. Anyone can download this one.",
                    KEEP_FIX + "Keep backups outside the website folder. Check what it contained."),
    "/phpmyadmin/": (_pma, "Medium", "Database admin page is public",
                     "Anyone can reach the login page of the database tool and try to break in.",
                     "Limit it to your own addresses or remove it. Use strong passwords."),
    "/wp-login.php": (_wp, "Low", "WordPress login page is public",
                      "This is normal, but it attracts password guessing.",
                      "Use strong passwords and two-step login, and limit login attempts."),
}


def _get(domain, port, path, timeout):
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = http.client.HTTPSConnection(domain, port, timeout=timeout, context=ctx)
    try:
        c.request("GET", path, headers={"User-Agent": UA})
        r = c.getresponse()
        return r.status, (r.getheader("Content-Type") or "").lower(), r.read(4096)
    finally:
        c.close()


def check_paths(domain, https_port=443, paths=None, timeout=8):
    domain = domain.strip().lower().rstrip(".")
    paths = paths or PATHS
    out, failed = [], 0
    for path, (detect, sev, title, why, fix) in paths.items():
        try:
            status, ct, body = _get(domain, https_port, path, timeout)
        except (OSError, http.client.HTTPException):
            failed += 1
            continue
        what = detect(status, ct, body)
        if what:
            # The evidence never includes the file contents.
            out.append(Finding(CHECK, domain, sev, title, f"https://{domain}{path} is readable by anyone.",
                               f"HTTPS GET {path} -> {status}; {what} (contents not stored)", why, fix, LIMIT))
    if failed == len(paths):
        return [Finding(CHECK, domain, "Info", "Exposed-file check could not complete",
                        "No secure response, so no files were checked.", "all requests failed",
                        "We could not check for exposed files.", "Fix HTTPS first, then run again.", LIMIT)]
    if not out:
        out.append(Finding(CHECK, domain, "Info", "No exposed files found",
                           f"{len(paths)} common file addresses were not readable.",
                           f"HTTPS GET on {len(paths)} paths", "Common leaks were not found.", "No action needed.", LIMIT))
    return out
