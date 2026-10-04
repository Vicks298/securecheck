# SecureCheck

A free security check for small businesses. You give it a domain. It checks the public side of the website and email. It writes a plain-English PDF report that says what to fix first.

Built for the Ubuntu Bridge Initiative Stage 9B final.

## The problem

Small businesses in Nigeria get hit by fake emails, unprotected websites and weak settings. Most cannot pay for a penetration test. They do not know what to ask their web host to fix.

SecureCheck looks at what any outsider can already see. It turns that into a short list of fixes an owner can hand to their web host or IT person.

## How it is used

SecureCheck is run by a person with basic technical skill, such as a security volunteer or a business's IT helper. The business owner does not run it. The owner gets the PDF report.

- Ask the owner for written permission. The consent form is `consent_form.pdf`.
- Run the check on their domain. It takes about a minute.
- Send them the PDF. Page one lists what to fix first, with steps their web host can follow.
- After they make changes, run it again and use `compare.py` to show what improved.

To try it without a real business, use the demo shop described below.

## What it checks

| Check | What it looks at |
|---|---|
| Email | SPF, DMARC, common DKIM selectors, MX |
| HTTPS | Certificate trust, name match, expiry; TLS 1.0 and 1.1; HSTS; HTTP to HTTPS redirect |
| Headers | Content-Security-Policy, clickjacking protection, X-Content-Type-Options, Referrer-Policy, server and technology disclosure, cookie flags |
| Ports | A plain connection test to 11 common ports. Flags risky ones such as Telnet, file sharing, Remote Desktop and databases |
| Exposed files | Six common addresses (for example `/.git/HEAD`, `/.env`, backups, `phpMyAdmin`). Each is confirmed by its content, not just by a 200 answer. Contents are never stored |
| Lookalikes | Spelling, typing and added-word variants of the domain, checked with DNS only. The lookalike sites are never opened |

Every finding stores a title, severity, what was found, the raw evidence with a time stamp, why it matters, exact fix steps, and the limit of the check.

## Severity

- **Critical:** data or control open to anyone right now, such as a public `.env`, `.git` folder or database backup.
- **High:** easy to abuse, such as no DMARC, SPF that allows anyone, an untrusted certificate, or a database or Remote Desktop port open to the internet.
- **Medium:** weakens defences, such as no HSTS, no redirect to HTTPS, no Content-Security-Policy, cookies without Secure.
- **Low:** small weaknesses, such as missing minor headers or a visible server version.
- **Info:** things that are fine, or checks that could not complete.

These ratings are my own rules, written in the code. They are not a published standard. Missing Content-Security-Policy is the only Medium header finding because it is the strongest of those protections.

## Run it

Needs Python 3.10 or newer.

```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 run.py example.com --by "Your Name" --json before.json --pdf report.pdf
```

To run only some checks: `--only email,tls`. Names are `email, tls, headers, ports, paths, lookalike`.

If the business owns other domains, list them so they are not reported as lookalikes: `--own other.com,other.ng`.

Check again after the owner makes changes, then compare:

```
python3 run.py example.com --json after.json --pdf report_after.pdf
python3 compare.py before.json after.json
```

### With Docker

```
docker build -t securecheck .
mkdir -p out
docker run --rm -v "$PWD/out:/out" securecheck example.com --by "Your Name" --json /out/before.json --pdf /out/report.pdf
```

### Tests

```
python3 -m pytest -q
```

The tests use local servers and a test certificate. They need the `openssl` command line tool.

## Demo business (free, runs on your own computer)

`lab/` holds a made-up shop called Demo Shop. It has a small web server and a small DNS server with deliberate weaknesses, and the same shop after the fixes. Nothing in it is real.

```
sh lab/make_certs.sh
echo "127.0.0.1 demo-shop.test" | sudo tee -a /etc/hosts
sh lab/demo.sh "Your Name"
```

This scans the shop before the fixes, applies them, scans again, and prints the comparison. It writes `before.pdf`, `after.pdf`, `before.json` and `after.json`.

This is a demonstration of the tool and the report. It is not a result from a real business.

## How it was checked

Results were compared with other tools on a live domain:

- Email results against `dig`.
- Certificate, HSTS, redirect and old-TLS results against `curl` and `openssl s_client`.
- Header results against `curl`.

One mismatch came up: `curl -I` (HEAD) showed a different Server header than a GET request. The server answers the two differently. SecureCheck uses GET, which is what browsers send.

## Limits

- It is an outside-in check of public information. It is not a penetration test.
- It never logs in, guesses passwords or looks at customer data.
- DKIM selectors are private names. "Not found" means not found among common names.
- Only the home page is requested for header checks. Other pages may differ.
- Port results depend on the network you scan from. "Filtered" is not the same as closed. On shared hosting the ports belong to the host's server.
- The exposed-file check looks at six addresses. A clean result does not mean nothing is exposed.
- A registered lookalike is not proof of abuse. It may belong to the owner. Only likely variants are tested.
- If a network's DNS answers for names that do not exist, the lookalike check refuses to report.
- If a network accepts connections on ports that should be closed, the port check refuses to report.
- The old-TLS test depends on this machine being able to attempt old protocols. A failed attempt does not prove the server refuses them.
- A slow network can stop a check. That is reported as "could not complete", not as a problem with the website.

## Ethics

Only check domains you own or have written permission to check. A consent form template is included in the project folder. The tool sends a small number of normal requests and does not attempt to break in or slow a site down. Files found by the exposed-file check are never saved, and the report says only that they were readable.

## Not built yet

- A web page where a business owner can type a domain and get the report without help.
- A staff awareness exercise. Volunteers who agreed in advance would get a safe link, and the report would count who opened it.
