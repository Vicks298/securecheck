import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from finding import Finding
from report import save_json, build_pdf
from compare import compare


def F(sev, title, check="email"):
    return Finding(check, "x.test", sev, title, "detail", "evidence <b>&", "why", "fix", "limit")


def test_pdf_and_json(tmp_path):
    fs = [F("High", "No DMARC record"), F("Medium", "SPF has no enforcement"), F("Info", "DKIM record found")]
    save_json("x.test", fs, tmp_path / "a.json", "Victor")
    build_pdf("x.test", fs, str(tmp_path / "a.pdf"), "Victor")
    assert (tmp_path / "a.pdf").stat().st_size > 1500
    assert json.load(open(tmp_path / "a.json"))["checked_by"] == "Victor"


def test_compare(tmp_path):
    save_json("x.test", [F("High", "No DMARC record"), F("Medium", "SPF has no enforcement")], tmp_path / "b.json")
    save_json("x.test", [F("Medium", "SPF has no enforcement"), F("Low", "No Referrer-Policy", "headers")], tmp_path / "a.json")
    out = compare(str(tmp_path / "b.json"), str(tmp_path / "a.json"))
    assert "Problems: 2 before -> 2 after" in out
    assert "Fixed (1)\n  [High] No DMARC record" in out
    assert "Still open (1)\n  [Medium] SPF has no enforcement" in out
    assert "New since the first scan (1)\n  [Low] No Referrer-Policy" in out
