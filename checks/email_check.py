"""Check 1: email protection (SPF, DMARC, DKIM, MX). DNS lookups only."""
import dns.resolver
import dns.exception
from finding import Finding

CHECK = "email"
DKIM_SELECTORS = ["default", "google", "selector1", "selector2",
                  "k1", "mail", "dkim", "s1", "s2"]
DKIM_LIMIT = ("DKIM selectors are private names. We only try common ones, "
              "so 'not found' does not prove DKIM is missing.")


def _txt(resolver, name):
    """Return TXT strings for a name. [] if none. None if the lookup failed."""
    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return None
    return ["".join(s.decode() for s in r.strings) for r in answers]


def _has_mx(resolver, domain):
    try:
        resolver.resolve(domain, "MX")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return None


def _spf(resolver, domain):
    out = []
    records = _txt(resolver, domain)
    if records is None:
        return [Finding(CHECK, domain, "Info", "SPF lookup failed",
                        "The DNS lookup timed out or failed.", "none",
                        "We could not check SPF.", "Run the check again.")]
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return [Finding(CHECK, domain, "High", "No SPF record",
                        "No SPF record was found for this domain.",
                        f"TXT {domain}: no v=spf1 record",
                        "Anyone can more easily send email that looks like it "
                        "comes from your business.",
                        "Ask your email provider for your SPF value. Add it as "
                        "a TXT record on your domain. It must end with -all or ~all.")]
    if len(spf) > 1:
        out.append(Finding(CHECK, domain, "Medium", "More than one SPF record",
                           "A domain must publish exactly one SPF record.",
                           " | ".join(spf),
                           "Receivers may reject all of them, so SPF may not work.",
                           "Merge the records into one record and delete the extras."))
    rec = spf[0].lower().split()
    ending = next((t for t in rec if t.endswith("all") and t.lstrip("+-~?") == "all"), None)
    if ending in ("+all", "all"):
        out.append(Finding(CHECK, domain, "High", "SPF allows any sender",
                           "The record ends with +all.", spf[0],
                           "It tells receivers that any server may send as you.",
                           "Change the ending to -all, or ~all while you test."))
    elif ending == "?all":
        out.append(Finding(CHECK, domain, "Medium", "SPF has no enforcement",
                           "The record ends with ?all (neutral).", spf[0],
                           "Receivers are told not to judge unlisted senders.",
                           "Change the ending to -all, or ~all while you test."))
    elif ending == "~all":
        out.append(Finding(CHECK, domain, "Low", "SPF uses soft fail",
                           "The record ends with ~all.", spf[0],
                           "Fake mail is marked suspicious but often still delivered.",
                           "When you are sure all real senders are listed, change to -all."))
    elif ending is None and not any(t.startswith("redirect=") for t in rec):
        out.append(Finding(CHECK, domain, "Medium", "SPF has no ending rule",
                           "The record has no all mechanism and no redirect.", spf[0],
                           "Unlisted senders are not clearly handled.",
                           "Add -all (or ~all while you test) at the end."))
    return out


def _dmarc(resolver, domain):
    name = f"_dmarc.{domain}"
    records = _txt(resolver, name)
    if records is None:
        return [Finding(CHECK, domain, "Info", "DMARC lookup failed",
                        "The DNS lookup timed out or failed.", "none",
                        "We could not check DMARC.", "Run the check again.")]
    dm = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dm:
        return [Finding(CHECK, domain, "High", "No DMARC record",
                        "No DMARC record was found.", f"TXT {name}: no v=DMARC1 record",
                        "Nothing tells receivers to block mail that fakes your domain.",
                        "Add a TXT record at _dmarc with: v=DMARC1; p=none; "
                        "rua=mailto:you@yourdomain. Review the reports, then move to "
                        "p=quarantine and later p=reject.")]
    tags = {}
    for part in dm[0].split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            tags[k.strip().lower()] = v.strip().lower()
    out = []
    policy = tags.get("p", "")
    if policy == "none":
        out.append(Finding(CHECK, domain, "Medium", "DMARC only monitors",
                           "Policy is p=none.", dm[0],
                           "Fake mail is reported but not blocked.",
                           "After reviewing reports, move to p=quarantine, then p=reject."))
    elif policy not in ("quarantine", "reject"):
        out.append(Finding(CHECK, domain, "Medium", "DMARC policy is invalid",
                           "The p= tag is missing or not recognised.", dm[0],
                           "Receivers may ignore the record.",
                           "Set p=none, p=quarantine or p=reject."))
    if "rua" not in tags:
        out.append(Finding(CHECK, domain, "Low", "No DMARC reports address",
                           "The record has no rua= tag.", dm[0],
                           "You will not see who is sending mail as your domain.",
                           "Add rua=mailto:an address you read."))
    return out


def _dkim(resolver, domain):
    found = []
    for sel in DKIM_SELECTORS:
        recs = _txt(resolver, f"{sel}._domainkey.{domain}")
        if recs and any("v=dkim1" in r.lower() or "p=" in r.lower() for r in recs):
            found.append(sel)
    if found:
        return [Finding(CHECK, domain, "Info", "DKIM record found",
                        f"Found selectors: {', '.join(found)}",
                        f"{found[0]}._domainkey.{domain}",
                        "Signed mail is easier to trust.", "No action needed.",
                        DKIM_LIMIT)]
    return [Finding(CHECK, domain, "Low", "DKIM not found among common selectors",
                    "None of the common selectors returned a key.",
                    "Tried: " + ", ".join(DKIM_SELECTORS),
                    "If DKIM is off, receivers cannot verify your mail is genuine.",
                    "Ask your email provider whether DKIM is on. Turn it on if not.",
                    DKIM_LIMIT)]


def check_email(domain, resolver=None):
    resolver = resolver or dns.resolver.Resolver()
    resolver.lifetime = 5
    domain = domain.strip().lower().rstrip(".")
    mx = _has_mx(resolver, domain)
    if mx is False:
        return [Finding(CHECK, domain, "Info", "Domain does not receive email",
                        "No MX record was found.", f"MX {domain}: none",
                        "Email checks matter less, but a domain that sends no mail "
                        "should still publish SPF -all and DMARC p=reject.",
                        "If you send no mail, publish: v=spf1 -all",
                        "The domain may still send mail without an MX record.")]
    return _spf(resolver, domain) + _dmarc(resolver, domain) + _dkim(resolver, domain)
