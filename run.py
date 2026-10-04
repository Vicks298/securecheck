import argparse
import re
import sys
from checks.email_check import check_email
from checks.tls_check import check_tls
from checks.headers_check import check_headers
from checks.ports_check import check_ports
from checks.paths_check import check_paths
from checks.lookalike_check import check_lookalikes
from finding import Finding
from report import sort_findings, save_json, build_pdf

def clean_domain(raw):
    """Turn what a person pastes (a web address, a path, a port) into a plain domain."""
    d = raw.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = re.split(r"[/?#]", d, maxsplit=1)[0]
    d = d.rsplit("@", 1)[-1].split(":")[0].rstrip(".")
    return d[4:] if d.startswith("www.") else d


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Security check for a domain you own or have permission to check.")
    ap.add_argument("domain")
    ap.add_argument("--json", help="save results to this JSON file")
    ap.add_argument("--pdf", help="save the report to this PDF file")
    ap.add_argument("--by", default="", help="name to show as 'Checked by'")
    ap.add_argument("--only", default="", help="run only these checks, comma-separated: email,tls,headers,ports,paths,lookalike")
    ap.add_argument("--dns", default="", help="use this DNS server, e.g. 127.0.0.1:5353 (lab demo)")
    ap.add_argument("--https-port", type=int, default=443, help="HTTPS port (lab demo)")
    ap.add_argument("--http-port", type=int, default=80, help="HTTP port (lab demo)")
    ap.add_argument("--ca-file", default=None, help="trust this CA file (lab demo)")
    ap.add_argument("--own", default="", help="comma-separated domains the business owns (not reported as lookalikes)")
    a = ap.parse_args()
    domain = clean_domain(a.domain)
    if "." not in domain:
        sys.exit(f"'{a.domain}' does not look like a domain. Use something like example.com")
    print(f"Checking {domain}\n")
    own = [o for o in a.own.split(",") if o.strip()]
    resolver = None
    if a.dns:
        import dns.resolver
        host, _, port = a.dns.partition(":")
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [host]
        resolver.port = int(port or 53)
    checks = [("email", lambda d: check_email(d, resolver)),
              ("tls", lambda d: check_tls(d, a.https_port, a.http_port, a.ca_file)),
              ("headers", lambda d: check_headers(d, a.https_port)),
              ("ports", check_ports),
              ("paths", lambda d: check_paths(d, a.https_port)),
              ("lookalike", lambda d: check_lookalikes(d, own, resolver))]
    only = {o.strip() for o in a.only.split(",") if o.strip()}
    if only:
        checks = [c for c in checks if c[0] in only]
    findings = []
    for name, fn in checks:
        try:
            findings += fn(domain)
        except Exception as e:  # one broken check must not stop the report
            findings.append(Finding(name, domain, "Info", f"{name} check failed to run", "The check hit an error.",
                                    f"{type(e).__name__}: {e}", "This part was not checked.", "Run it again."))
    findings = sort_findings(findings)
    for f in findings:
        print(f"[{f.severity}] ({f.check}) {f.title}")
        print(f"   {f.detail}")
        if f.severity != "Info":
            print(f"   Fix: {f.fix}")
        print(f"   Evidence: {f.evidence[:300]}")
        if f.limit:
            print(f"   Limit: {f.limit}")
        print()
    if a.json:
        save_json(domain, findings, a.json, a.by)
        print(f"Saved {a.json}")
    if a.pdf:
        build_pdf(domain, findings, a.pdf, a.by)
        print(f"Saved {a.pdf}")
