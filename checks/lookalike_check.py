"""Check 6: lookalike domains. DNS lookups only. Never opens the lookalike sites."""
import random
import string
from concurrent.futures import ThreadPoolExecutor
import dns.exception
import dns.resolver
from finding import Finding

CHECK = "lookalike"
MULTI = ("com.ng", "org.ng", "net.ng", "edu.ng", "gov.ng", "co.uk", "co.za")
COMMON_TLDS = ("com", "ng", "com.ng", "net", "org")
KEYWORDS = ("login", "secure", "support", "pay")
HOMOGLYPH = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "m": ["rn"]}
LIMIT = ("A registered lookalike is not proof of abuse. It may belong to the owner or be unrelated. "
         "We only test likely spelling and typing variants, not every possible name, and we do not "
         "open the sites to see what they show.")


def split_domain(domain):
    d = domain.strip().lower().rstrip(".")
    d = d[4:] if d.startswith("www.") else d
    for m in sorted(MULTI, key=len, reverse=True):
        if d.endswith("." + m):
            return d[:-len(m) - 1].split(".")[-1], m
    label, _, tld = d.rpartition(".")
    return label.split(".")[-1], tld


def variants(domain):
    label, tld = split_domain(domain)
    base = f"{label}.{tld}"
    out = {}

    def add(lab, t, kind):
        name = f"{lab}.{t}"
        if lab and not lab.startswith("-") and not lab.endswith("-") and name != base and name not in out:
            out[name] = kind

    n = len(label)
    if n >= 4:
        for i in range(n):
            add(label[:i] + label[i + 1:], tld, "missing letter")
    for i in range(n):
        add(label[:i + 1] + label[i] + label[i + 1:], tld, "doubled letter")
    for i in range(n - 1):
        if label[i] != label[i + 1]:
            add(label[:i] + label[i + 1] + label[i] + label[i + 2:], tld, "swapped letters")
    for i, ch in enumerate(label):
        for rep in HOMOGLYPH.get(ch, []):
            add(label[:i] + rep + label[i + 1:], tld, "look-alike character")
    for i in range(1, n):
        add(label[:i] + "-" + label[i:], tld, "added hyphen")
    for k in KEYWORDS:
        add(f"{label}-{k}", tld, "added word")
        add(f"{k}-{label}", tld, "added word")
    for t in COMMON_TLDS:
        if t != tld:
            add(label, t, "different ending")
    return out


def _lookup(resolver, name):
    """None if not registered. Otherwise {'a': [...], 'mx': bool}."""
    a = []
    try:
        a = [r.to_text() for r in resolver.resolve(name, "A")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return None
    if not a:
        try:
            resolver.resolve(name, "NS")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
            return None
    try:
        resolver.resolve(name, "MX")
        mx = True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
        mx = False
    return {"a": a, "mx": mx}


def check_lookalikes(domain, own=(), resolver=None):
    domain = domain.strip().lower().rstrip(".")
    resolver = resolver or dns.resolver.Resolver()
    resolver.lifetime = 3
    # Some networks answer for names that do not exist. Then every name looks registered.
    fake = "".join(random.choices(string.ascii_lowercase, k=14)) + ".com"
    if _lookup(resolver, fake) is not None:
        return [Finding(CHECK, domain, "Info", "Lookalike check could not complete",
                        "This network's DNS answers for names that do not exist.", f"{fake} resolved",
                        "Results would be wrong, so none are shown.",
                        "Run the check again from a different network or DNS server.", LIMIT)]
    skip = {o.strip().lower() for o in own} | {domain}
    cands = {n: k for n, k in variants(domain).items() if n not in skip}
    names = list(cands)
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = dict(zip(names, pool.map(lambda n: _lookup(resolver, n), names)))
    hits = {n: r for n, r in results.items() if r is not None}
    if not hits:
        return [Finding(CHECK, domain, "Info", "No registered lookalikes found",
                        f"{len(cands)} likely variants were tested and none are registered.",
                        f"{len(cands)} DNS lookups", "Fewer fake copies of the name are likely.",
                        "No action needed.", LIMIT)]
    active = [n for n, r in hits.items() if r["a"] or r["mx"]]
    sev = "Medium" if active else "Low"

    def show(n, r):
        bits = [f"{cands[n]}"] + (["website address"] if r["a"] else []) + (["can receive mail"] if r["mx"] else [])
        return f"{n} ({', '.join(bits)})"

    shown = sorted(hits)[:10]
    more = f" and {len(hits) - 10} more" if len(hits) > 10 else ""
    return [Finding(CHECK, domain, sev, "Lookalike domains are registered",
                    f"{len(hits)} lookalike names of {domain} are registered.",
                    "; ".join(show(n, hits[n]) for n in shown) + more,
                    "Lookalike names are used for fake emails and fake websites that copy a business.",
                    "Check each name. If it is not yours and looks like a copy of your business, report it to "
                    "the registrar and warn your customers. Register the ones you can.", LIMIT)]
