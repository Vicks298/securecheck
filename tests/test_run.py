import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from run import clean_domain


def test_plain_domain_is_unchanged():
    assert clean_domain("example.com") == "example.com"


def test_pasted_web_addresses_are_cleaned():
    assert clean_domain("https://www.Example.com/shop?id=1#top") == "example.com"
    assert clean_domain("http://example.com:8080/") == "example.com"
    assert clean_domain("  example.com.  ") == "example.com"
    assert clean_domain("https://user@example.com.ng/") == "example.com.ng"
