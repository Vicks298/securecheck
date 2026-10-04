import os, sys
import dns.resolver
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from checks.lookalike_check import check_lookalikes, variants, split_domain


class R:
    def __init__(self, t): self.t = t
    def to_text(self): return self.t


class Fake:
    def __init__(self, zone=None, everything=False):
        self.zone, self.everything, self.lifetime = zone or {}, everything, 0
    def resolve(self, name, rtype):
        if self.everything:
            return [R("1.2.3.4")]
        if (name, rtype) not in self.zone:
            raise dns.resolver.NXDOMAIN()
        return [R(x) for x in self.zone[(name, rtype)]]


def titles(fs):
    return {(f.severity, f.title) for f in fs}


def test_split_domain():
    assert split_domain("www.Acme.com.ng") == ("acme", "com.ng")
    assert split_domain("shop.acme.com") == ("acme", "com")


def test_variants_cover_the_main_tricks():
    v = variants("acmepay.com")
    for name in ("acmepa.com", "acmepay.ng", "acmepay.com.ng", "acmepay-login.com",
                 "secure-acmepay.com", "acmepya.com", "acm-epay.com", "acmepaay.com"):
        assert name in v, name
    assert "acmepay.com" not in v
    assert variants("goal.com")["g0al.com"] == "look-alike character"


def test_nothing_registered():
    t = titles(check_lookalikes("acmepay.com", resolver=Fake()))
    assert t == {("Info", "No registered lookalikes found")}


def test_registered_lookalike_with_mail_is_medium():
    zone = {("acmepay-login.com", "A"): ["5.6.7.8"], ("acmepay-login.com", "MX"): ["10 m"]}
    fs = check_lookalikes("acmepay.com", resolver=Fake(zone))
    assert titles(fs) == {("Medium", "Lookalike domains are registered")}
    assert "acmepay-login.com" in fs[0].evidence and "can receive mail" in fs[0].evidence


def test_registered_without_records_is_low():
    zone = {("acmepay.ng", "NS"): ["ns1.parked.test"]}
    assert titles(check_lookalikes("acmepay.com", resolver=Fake(zone))) == {("Low", "Lookalike domains are registered")}


def test_owner_domains_are_ignored():
    zone = {("acmepay.ng", "A"): ["5.6.7.8"]}
    t = titles(check_lookalikes("acmepay.com", own=["acmepay.ng"], resolver=Fake(zone)))
    assert t == {("Info", "No registered lookalikes found")}


def test_dns_that_answers_for_everything_is_not_trusted():
    t = titles(check_lookalikes("acmepay.com", resolver=Fake(everything=True)))
    assert t == {("Info", "Lookalike check could not complete")}
