"""Check 4: open ports. A plain TCP connect to a short list of ports. Nothing is sent."""
import random
import socket
from concurrent.futures import ThreadPoolExecutor
from finding import Finding

CHECK = "ports"
# port: (name, severity or None, why it matters, fix). None = normal, no finding.
PORTS = {
    21: ("FTP", "Medium", "FTP sends passwords and files in plain text unless it is secured.",
         "Close port 21, or switch to SFTP or FTPS."),
    22: ("SSH remote login", "Low", "Anyone on the internet can try to guess the login, and attackers do.",
         "Allow SSH only from your own addresses, use keys, and turn off password login."),
    23: ("Telnet", "High", "Telnet sends everything, including passwords, in plain text.",
         "Close port 23 and use SSH instead."),
    25: ("Mail (SMTP)", None, "", ""),
    80: ("Web (HTTP)", None, "", ""),
    443: ("Web (HTTPS)", None, "", ""),
    445: ("Windows file sharing (SMB)", "High",
          "File sharing should not be open to the internet. Attackers scan for it all the time.",
          "Block port 445 at the firewall."),
    3306: ("MySQL database", "High", "A database open to the internet can be attacked directly.",
           "Block port 3306 at the firewall. Let only the web server reach the database."),
    3389: ("Remote Desktop (RDP)", "High", "Remote Desktop open to the internet is a common way in for attackers.",
           "Block port 3389. Use a VPN for remote access."),
    5432: ("PostgreSQL database", "High", "A database open to the internet can be attacked directly.",
           "Block port 5432 at the firewall. Let only the web server reach the database."),
    8080: ("Extra web port", "Low", "A second web service is often a test or admin page that was forgotten.",
           "Check what runs on this port. Close it if it is not needed."),
}
LIMIT = ("This is a plain connection test from one network to a short list of ports. "
         "'Filtered' means no answer, which is not the same as closed. Results can change "
         "with the network you scan from. On shared hosting these ports belong to the hosting "
         "company's server, not only to this business.")


def _probe(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError:  # includes timeouts
        return "filtered"


def check_ports(domain, ports=None, timeout=3, controls=None):
    domain = domain.strip().lower().rstrip(".")
    ports = ports or PORTS
    try:
        ip = socket.getaddrinfo(domain, None, socket.AF_INET)[0][4][0]
    except (socket.gaierror, IndexError) as e:
        return [Finding(CHECK, domain, "Info", "Port check could not complete",
                        "The domain name did not resolve to an address.", f"{type(e).__name__}: {e}",
                        "We could not test any ports.", "Check the internet connection and the domain name.", LIMIT)]
    # Control ports: ports that should be closed. If one answers, something on the path
    # (a proxy, a firewall, a tarpit) accepts every connection and the results mean nothing.
    controls = controls or [1, random.randint(49152, 65535)]
    probe_list = list(ports) + [c for c in controls if c not in ports]
    with ThreadPoolExecutor(max_workers=13) as pool:
        got = dict(zip(probe_list, pool.map(lambda p: _probe(ip, p, timeout), probe_list)))
    states = {p: got[p] for p in ports}
    bad = [str(c) for c in controls if got.get(c) == "open"]
    if bad:
        return [Finding(CHECK, domain, "Info", "Port check could not complete",
                        "Ports that should be closed accepted a connection, so the results cannot be trusted.",
                        f"{ip}: control ports open: {', '.join(bad)}",
                        "A device between us and the site, or the site itself, accepts every connection.",
                        "Run the check again from a different network, such as a phone hotspot.", LIMIT)]
    out = []
    for port, state in states.items():
        name, sev, why, fix = ports[port]
        if state == "open" and sev:
            out.append(Finding(CHECK, domain, sev, f"{name} is open to the internet",
                               f"Port {port} accepted a connection.",
                               f"TCP connect to {ip}:{port} succeeded", why, fix, LIMIT))
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
