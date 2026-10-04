import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import dns.resolver
from checks.email_check import check_email


class Rdata:
    def __init__(self, text): self.strings = [text.encode()]


class FakeResolver:
    def __init__(self, zone): self.zone, self.lifetime = zone, 0
    def resolve(self, name, rtype):
        key = (name, rtype)
        if key not in self.zone:
            raise dns.resolver.NXDOMAIN()
        return [Rdata(t) for t in self.zone[key]]


def titles(zone, domain="x.test"):
    return {(f.severity, f.title) for f in check_email(domain, FakeResolver(zone))}


def test_nothing_published():
    t = titles({("x.test", "MX"): ["10 mail.x.test"]})
    assert ("High", "No SPF record") in t
    assert ("High", "No DMARC record") in t
    assert ("Low", "DKIM not found among common selectors") in t


def test_good_setup():
    t = titles({("x.test", "MX"): ["10 m"],
                ("x.test", "TXT"): ["v=spf1 include:_spf.google.com -all"],
                ("_dmarc.x.test", "TXT"): ["v=DMARC1; p=reject; rua=mailto:a@x.test"],
                ("google._domainkey.x.test", "TXT"): ["v=DKIM1; k=rsa; p=ABC"]})
    assert all(sev == "Info" for sev, _ in t), t


def test_weak_values():
    t = titles({("x.test", "MX"): ["10 m"],
                ("x.test", "TXT"): ["v=spf1 +all"],
                ("_dmarc.x.test", "TXT"): ["v=DMARC1; p=none"]})
    assert ("High", "SPF allows any sender") in t
    assert ("Medium", "DMARC only monitors") in t
    assert ("Low", "No DMARC reports address") in t


def test_two_spf_and_softfail():
    t = titles({("x.test", "MX"): ["10 m"],
                ("x.test", "TXT"): ["v=spf1 ~all", "v=spf1 -all"],
                ("_dmarc.x.test", "TXT"): ["v=DMARC1; p=quarantine; rua=mailto:a@x.test"]})
    assert ("Medium", "More than one SPF record") in t
    assert ("Low", "SPF uses soft fail") in t


def test_no_mx():
    t = titles({})
    assert t == {("Info", "Domain does not receive email")}
