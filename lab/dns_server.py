"""A tiny DNS server with made-up email records for demo-shop.test.
   python3 lab/dns_server.py weak|fixed
Listens on 127.0.0.1:5353. Not a real domain."""
import socket
import sys
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

ZONES = {
    "weak": {
        "demo-shop.test.": {"MX": ["10 mail.demo-shop.test."], "TXT": ['"v=spf1 +all"']},
    },
    "fixed": {
        "demo-shop.test.": {"MX": ["10 mail.demo-shop.test."], "TXT": ['"v=spf1 mx -all"']},
        "_dmarc.demo-shop.test.": {"TXT": ['"v=DMARC1; p=quarantine; rua=mailto:dmarc@demo-shop.test"']},
        "default._domainkey.demo-shop.test.": {"TXT": ['"v=DKIM1; k=rsa; p=DEMOKEYNOTREAL"']},
    },
}


def answer(zone, wire):
    q = dns.message.from_wire(wire)
    r = dns.message.make_response(q)
    r.flags |= dns.flags.AA
    name = q.question[0].name.to_text().lower()
    rtype = dns.rdatatype.to_text(q.question[0].rdtype)
    if name not in zone:
        r.set_rcode(dns.rcode.NXDOMAIN)
    elif zone[name].get(rtype):
        r.answer.append(dns.rrset.from_text(name, 60, "IN", rtype, *zone[name][rtype]))
    return r.to_wire()


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ZONES:
        sys.exit("usage: python3 lab/dns_server.py weak|fixed")
    zone = ZONES[sys.argv[1]]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 5353))
    print(f"Demo DNS ({sys.argv[1]}) on 127.0.0.1:5353. Ctrl+C to stop.")
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            try:
                sock.sendto(answer(zone, data), addr)
            except Exception:
                pass
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
