import os, socket, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from checks import ports_check
from checks.ports_check import check_ports

TELNET = ("Telnet", "High", "why", "fix")


def listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(5)
    return s, s.getsockname()[1]


def free_port():
    s, p = listener()
    s.close()
    return p


def titles(fs):
    return {(f.severity, f.title) for f in fs}


def test_open_risky_port_is_flagged():
    s, port = listener()
    t = titles(check_ports("127.0.0.1", {port: TELNET}))
    s.close()
    assert ("High", "Telnet is open to the internet") in t
    assert ("Info", "Port check summary") in t


def test_closed_port_is_not_a_finding():
    t = titles(check_ports("127.0.0.1", {free_port(): TELNET}))
    assert t == {("Info", "Port check summary")}


def test_normal_open_port_is_not_a_finding():
    s, port = listener()
    t = titles(check_ports("127.0.0.1", {port: ("Web (HTTPS)", None, "", "")}))
    s.close()
    assert t == {("Info", "Port check summary")}


def test_all_filtered(monkeypatch):
    def slow(*a, **k):
        raise socket.timeout("no answer")
    monkeypatch.setattr(ports_check.socket, "create_connection", slow)
    t = titles(check_ports("127.0.0.1", {1: TELNET, 2: TELNET}))
    assert t == {("Info", "No ports answered")}


def test_unresolvable_domain():
    t = titles(check_ports("no-such-host.invalid"))
    assert t == {("Info", "Port check could not complete")}


def test_network_that_accepts_everything_is_not_trusted():
    s, control = listener()
    s2, telnet = listener()
    t = titles(check_ports("127.0.0.1", {telnet: TELNET}, controls=[control]))
    s.close(); s2.close()
    assert t == {("Info", "Port check could not complete")}
