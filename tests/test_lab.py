import os, sys
import dns.message, dns.rcode
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "lab"))
from dns_server import ZONES, answer


def ask(mode, name, rtype):
    q = dns.message.make_query(name, rtype)
    return dns.message.from_wire(answer(ZONES[mode], q.to_wire()))


def test_weak_zone_has_open_spf_and_no_dmarc():
    r = ask("weak", "demo-shop.test", "TXT")
    assert "+all" in r.answer[0].to_text()
    assert ask("weak", "_dmarc.demo-shop.test", "TXT").rcode() == dns.rcode.NXDOMAIN


def test_fixed_zone_has_dmarc_and_dkim():
    assert "p=quarantine" in ask("fixed", "_dmarc.demo-shop.test", "TXT").answer[0].to_text()
    assert "DKIM1" in ask("fixed", "default._domainkey.demo-shop.test", "TXT").answer[0].to_text()


def test_name_with_no_data_is_empty_not_missing():
    r = ask("weak", "demo-shop.test", "A")
    assert r.rcode() == dns.rcode.NOERROR and not r.answer
