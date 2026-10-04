"""Check 4: open ports.
A TCP connect to a short list of ports. Where a service has a standard greeting, we also
send one harmless first message and check the reply. A proxy or firewall that only completes
connections cannot fake the reply, so a port that connects but does not answer properly
makes the whole scan untrusted."""
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from finding import Finding

CHECK = "ports"
BANNER_WAIT = 4  # seconds to wait for a reply after connecting
HTTP_HEAD = b"HEAD / HTTP/1.0\r\n\r\n"
PG_SSL_REQUEST = bytes.fromhex("0000000804d2162f")  # PostgreSQL's standard first request

# verifier name: (first message to send, test of the reply)
VERIFIERS = {
    "ftp": (b"", lambda d: d.startswith(b"220")),
    "smtp": (b"", lambda d: d.startswith(b"220")),
    "ssh": (b"", lambda d: d.startswith(b"SSH-")),
    "mysql": (b"", lambda d: len(d) > 4 and d[4] in (0x0A, 0xFF)),
    "postgres": (PG_SSL_REQUEST, lambda d: d[:1] in (b"S", b"N")),
    "http": (HTTP_HEAD, lambda d: d.startswith(b"HTTP/")),
}
# port: (name, severity or None, why it matters, fix, verifier or None). None severity = normal.
PORTS = {
    21: ("FTP", "Medium", "FTP sends passwords and files in plain text unless it is secured.",
         "Close port 21, or switch to SFTP or FTPS.", "ftp"),
    22: ("SSH remote login", "Low", "Anyone on the internet can try to guess the login, and attackers do.",
         "Allow SSH only from your own addresses, use keys, and turn off password login.", "ssh"),
    23: ("Telnet", "High", "Telnet sends everything, including passwords, in plain text.",
         "Close port 23 and use SSH instead.", None),
    25: ("Mail (SMTP)", None, "", "", "smtp"),
    80: ("Web (HTTP)", None, "", "", "http"),
    443: ("Web (HTTPS)", None, "", "", None),
    445: ("Windows file sharing (SMB)", "High",
          "File sharing should not be open to the internet. Attackers scan for it all the time.",
          "Block port 445 at the firewall.", None),
    3306: ("MySQL database", "High", "A database open to the internet can be attacked directly.",
           "Block port 3306 at the firewall. Let only the web server reach the database.", "mysql"),
    3389: ("Remote Desktop (RDP)", "High", "Remote Desktop open to the internet is a common way in for attackers.",
           "Block port 3389. Use a VPN for remote access.", None),
    5432: ("PostgreSQL database", "High", "A database open to the internet can be attacked directly.",
           "Block port 5432 at the firewall. Let only the web server reach the database.", "postgres"),
    8080: ("Extra web port", "Low", "A second web service is often a test or admin page that was forgotten.",
           "Check what runs on this port. Close it if it is not needed.", "http"),
}
LIMIT = ("This is a connection test from one network to a short list of ports. Open ports are "
         "confirmed by the service's first reply where it has a standard one (not for Telnet, "
         "SMB, Remote Desktop or HTTPS). 'Filtered' means no answer, which is not the same as "
         "closed. Results can change with the network you scan from. On shared hosting these "
         "ports belong to the hosting company's server, not only to this business.")


def _probe(ip, port, timeout, verifier):
    """Returns (state, verified, milliseconds). verified: True, False, or None if not checked."""
    start = time.perf_counter()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        return "closed", None, 0.0
    except OSError:  # includes timeouts
        return "filtered", None, 0.0
    ms = (time.perf_counter() - start) * 1000
    with s:
        if verifier not in VERIFIERS:
            return "open", None, ms
        send, ok = VERIFIERS[verifier]
        data = b""
        try:
            s.settimeout(BANNER_WAIT)
            if send:
                s.sendall(send)
            data = s.recv(256)
        except OSError:
            pass
        return "open", bool(data) and bool(ok(data)), ms


def check_ports(domain, ports=None, timeout=3, controls=None):
    domain = domain.strip().lower().rstrip(".")
    ports = ports or PORTS
    try:
        ip = socket.getaddrinfo(domain, None, socket.AF_INET)[0][4][0]
    except (socket.gaierror, IndexError) as e:
        return [Finding(CHECK, domain, "Info", "Port check could not complete",
                        "The domain name did not resolve to an address.", f"{type(e).__name__}: {e}",
                        "We could not test any ports.", "Check the internet connection and the domain name.", LIMIT)]
    # Control ports should be closed. If one answers, something on the path accepts everything.
    controls = controls or [1, random.randint(49152, 65535)]
    probe_list = list(ports) + [c for c in controls if c not in ports]
    with ThreadPoolExecutor(max_workers=14) as pool:
        got = dict(zip(probe_list, pool.map(
            lambda p: _probe(ip, p, timeout, ports[p][4] if p in ports else None), probe_list)))
    bad_controls = [f"{c} (should be closed)" for c in controls if got[c][0] == "open"]
    bad_replies = [f"{p} ({ports[p][0]}): connected, but the expected reply did not come"
                   for p in ports if got[p][0] == "open" and got[p][1] is False]
    if bad_controls or bad_replies:
        return [Finding(CHECK, domain, "Info", "Port check could not complete",
                        "Some ports accepted a connection but did not behave like the real service, "
                        "so the results cannot be trusted.",
                        f"{ip}: " + "; ".join(bad_controls + bad_replies),
                        "A proxy or firewall between us and the site, or the site itself, may be "
                        "accepting connections on its behalf.",
                        "Run the check again from a different network, such as a phone hotspot.", LIMIT)]
    states = {p: got[p][0] for p in ports}
    out = []
    for port, state in states.items():
        name, sev, why, fix, _ = ports[port]
        if state == "open" and sev:
            checked = ", first reply matched" if got[port][1] else ""
            out.append(Finding(CHECK, domain, sev, f"{name} is open to the internet",
                               f"Port {port} accepted a connection.",
                               f"TCP connect to {ip}:{port} succeeded in {got[port][2]:.1f} ms{checked}",
                               why, fix, LIMIT))
    groups = {k: [str(p) for p, s in states.items() if s == k] for k in ("open", "closed", "filtered")}
    summary = "; ".join(f"{k}: {', '.join(v) or 'none'}" for k, v in groups.items())
    if len(groups["filtered"]) == len(states):
        out.append(Finding(CHECK, domain, "Info", "No ports answered",
                           "Every port looked filtered. The host may be down, or this network blocks scans.",
                           f"{ip} -> {summary}", "We cannot say which ports are open.",
                           "Try again from a different network.", LIMIT))
    else:
        out.append(Finding(CHECK, domain, "Info", "Port check summary", f"Tested {len(states)} common ports.",
                           f"{ip} -> {summary}", "Shows what an outsider can reach.", "No action needed.", LIMIT))
    return out
