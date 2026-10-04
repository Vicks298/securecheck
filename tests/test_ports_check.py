import os, socket, sys, threading, time
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from checks import ports_check
from checks.ports_check import check_ports

TELNET = ("Telnet", "High", "why", "fix", None)
NORMAL = ("Web (HTTPS)", None, "", "", None)


@pytest.fixture(autouse=True)
def fast_banner(monkeypatch):
    monkeypatch.setattr(ports_check, "BANNER_WAIT", 0.4)


def listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(5)
    return s, s.getsockname()[1]


def free_port():
    s, p = listener()
    s.close()
    return p


def fake_service(banner=b"", reply=None):
    """A tiny server. Sends a banner on connect, or answers the first message with `reply`."""
    s, port = listener()
    held = []

    def run():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            held.append(c)
            try:
                if banner:
                    c.sendall(banner)
                if reply is not None:
                    c.settimeout(1)
                    c.recv(256)
                    c.sendall(reply)
            except OSError:
                pass

    threading.Thread(target=run, daemon=True).start()
    return s, port


def titles(fs):
    return {(f.severity, f.title) for f in fs}


def test_open_risky_port_is_flagged():
    s, port = listener()
    t = titles(check_ports("127.0.0.1", {port: TELNET}))
    s.close()
    assert ("High", "Telnet is open to the internet") in t
    assert ("Info", "Port check summary") in t


def test_closed_port_is_not_a_finding():
    assert titles(check_ports("127.0.0.1", {free_port(): TELNET})) == {("Info", "Port check summary")}


def test_normal_open_port_is_not_a_finding():
    s, port = listener()
    assert titles(check_ports("127.0.0.1", {port: NORMAL})) == {("Info", "Port check summary")}
    s.close()


def test_all_filtered(monkeypatch):
    def slow(*a, **k):
        raise socket.timeout("no answer")
    monkeypatch.setattr(ports_check.socket, "create_connection", slow)
    assert titles(check_ports("127.0.0.1", {1: TELNET, 2: TELNET})) == {("Info", "No ports answered")}


def test_unresolvable_domain():
    assert titles(check_ports("no-such-host.invalid")) == {("Info", "Port check could not complete")}


def test_network_that_accepts_everything_is_not_trusted():
    s, control = listener()
    s2, telnet = listener()
    t = titles(check_ports("127.0.0.1", {telnet: TELNET}, controls=[control]))
    s.close(); s2.close()
    assert t == {("Info", "Port check could not complete")}


def test_real_ssh_banner_is_confirmed():
    s, port = fake_service(banner=b"SSH-2.0-OpenSSH_9.6\r\n")
    fs = check_ports("127.0.0.1", {port: ("SSH remote login", "Low", "why", "fix", "ssh")})
    s.close()
    assert ("Low", "SSH remote login is open to the internet") in titles(fs)
    assert "first reply matched" in next(f for f in fs if f.severity == "Low").evidence


def test_silent_port_that_should_greet_makes_scan_untrusted():
    # This is what a proxy that only completes connections looks like.
    s, port = fake_service()
    fs = check_ports("127.0.0.1", {port: ("SSH remote login", "Low", "why", "fix", "ssh")})
    s.close()
    assert titles(fs) == {("Info", "Port check could not complete")}
    assert "expected reply did not come" in fs[0].evidence


def test_one_fake_port_taints_the_whole_scan():
    real, rport = fake_service(banner=b"SSH-2.0-x\r\n")
    fake, fport = fake_service()  # silent "MySQL"
    ports = {rport: ("SSH remote login", "Low", "w", "f", "ssh"),
             fport: ("MySQL database", "High", "w", "f", "mysql")}
    t = titles(check_ports("127.0.0.1", ports))
    real.close(); fake.close()
    assert t == {("Info", "Port check could not complete")}


def test_mysql_postgres_http_ftp_replies():
    cases = [
        ("mysql", b"\x4a\x00\x00\x00\x0a8.0.36\x00", None),
        ("postgres", None, b"N"),
        ("http", None, b"HTTP/1.1 200 OK\r\n\r\n"),
        ("ftp", b"220 FTP ready\r\n", None),
    ]
    for verifier, banner, reply in cases:
        s, port = fake_service(banner=banner or b"", reply=reply)
        fs = check_ports("127.0.0.1", {port: ("Thing", "High", "w", "f", verifier)})
        s.close()
        assert ("High", "Thing is open to the internet") in titles(fs), verifier
