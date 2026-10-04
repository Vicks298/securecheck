# SecureCheck

A free security check for small businesses. You give it a domain. It checks the public side of the website and email. It writes a plain-English PDF report that says what to fix first.

Built for the Ubuntu Bridge Initiative Stage 9B final.

## What it is

SecureCheck finds the unlocked doors. A penetration test goes through them.

It looks only at what any stranger on the internet can already see. It reports what is set up badly or left exposed. It never logs in, guesses a password or touches customer data. It is not a penetration test.

## The problem

Small businesses in Nigeria get hit by fake emails, unprotected websites and weak settings. Most cannot pay for a penetration test. They do not know what to ask their web host to fix.

SecureCheck turns what an outsider can see into a short list of fixes. The owner can hand that list to their web host or IT person.

## Who uses it

A person with basic technical skill runs it. That could be a security volunteer or a business's IT helper.

The business owner does not run it. The owner gets the PDF report.

## Before you start

Only check a domain you own, or one the owner has agreed in writing that you may check. A consent form is in this folder: `consent_form.pdf`.

## Two ways to run it

- **Option A. Python.** You install a few Python packages. Good if you already use Python.
- **Option B. Docker.** Docker packs the tool and everything it needs into one image. Nothing else is installed on your computer. Good if you use Docker, or do not want to set up Python.

The results are the same either way. Pick one.

## Option A. Python, step by step

### Step 1. Check that you have Python and git

```
python3 --version
git --version
```

You need Python 3.10 or newer, and git. On Windows, use WSL or Option B (Docker).

### Step 2. Download the tool

```
git clone https://github.com/Vicks298/securecheck.git
cd securecheck
```

### Step 3. Set it up (once)

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Each time you open a new terminal, go to the `securecheck` folder and run `source .venv/bin/activate` again.

### Step 4. Run the check on a domain

```
python3 run.py mybusiness.com --by "Your Name" --json before.json --pdf report.pdf
```

Replace each part like this:

- `mybusiness.com` is the domain to check. Type the domain only. If you paste a full web address, SecureCheck removes the `https://`, the `www.` and the path for you.
- `--by "Your Name"` is optional. It adds a "Checked by" line to the report. Put the name of the person who ran the check inside the quotes. Leave the whole part out if you do not want it.
- `--json before.json` saves the results to a file. You need this file later to compare. Pick a clear name for each business, for example `clinic_before.json`.
- `--pdf report.pdf` saves the report you give to the business. Pick a clear name here too. A file with the same name is overwritten.

The check takes about a minute. The terminal prints each finding as it goes.

### Step 5. Read the result

The PDF is saved in the same folder. Open it:

```
xdg-open report.pdf
```

On a Mac, use `open report.pdf`.

- Page 1 lists what to fix first, in plain English, with steps.
- Page 2 has the technical details and the evidence for each finding.

### Step 6. Give the report to the owner

The owner passes it to their web host or IT person. Page 1 tells them what to change.

### Step 7. Check again after the fixes

```
python3 run.py mybusiness.com --by "Your Name" --json after.json --pdf report_after.pdf
python3 compare.py before.json after.json
```

`compare.py` prints three lists:

- Fixed: problems in the first scan that are gone.
- Still open: problems that remain.
- New since the first scan: problems that were not there before.

## Option B. Docker, step by step

### Step 1. Check that Docker works

```
docker --version
```

If the command is not found, install Docker first. You also need git. If you do not have git, download the project as a ZIP file from the GitHub page and open the folder instead.

### Step 2. Download the tool

```
git clone https://github.com/Vicks298/securecheck.git
cd securecheck
```

### Step 3. Build the image (once)

```
docker build -t securecheck .
```

The first build takes a few minutes, because Docker downloads Python and the packages.

- `-t securecheck` gives the image a name.
- The dot at the end means "use this folder".

### Step 4. Make a folder for the results

```
mkdir -p out
```

### Step 5. Run the check on a domain

```
docker run --rm -v "$PWD/out:/out" securecheck mybusiness.com --by "Your Name" --json /out/before.json --pdf /out/report.pdf
```

Replace each part like this:

- `docker run --rm` runs the tool, then removes the container.
- `-v "$PWD/out:/out"` links the `out` folder on your computer to the `/out` folder inside Docker. This is how the files reach you.
- `securecheck` is the image you built in Step 3.
- `mybusiness.com` is the domain to check. Type the domain only.
- `--by "Your Name"` is optional. It adds a "Checked by" line to the report.
- `--json` and `--pdf` save the results and the report. The file paths must start with `/out/`. Use clear names for each business.

### Step 6. Read the result

Your files are now in the `out` folder on your computer. Open the report:

```
xdg-open out/report.pdf
```

On a Mac, use `open out/report.pdf`.

- Page 1 lists what to fix first, in plain English, with steps.
- Page 2 has the technical details and the evidence for each finding.

Give the report to the owner. They pass it to their web host or IT person.

### Step 7. Check again after the fixes

```
docker run --rm -v "$PWD/out:/out" securecheck mybusiness.com --by "Your Name" --json /out/after.json --pdf /out/report_after.pdf
docker run --rm -v "$PWD/out:/out" --entrypoint python securecheck compare.py /out/before.json /out/after.json
```

The first command scans again. The second runs `compare.py` inside the image. It prints three lists: Fixed, Still open, and New since the first scan.

### Notes on Docker

- If you change the code, run Step 3 again to rebuild the image.
- The demo shop below does not run inside Docker. Use Option A for the demo.

## All options

| Option | What it does |
|---|---|
| `--by "Name"` | Adds a "Checked by" line to the report. Optional. |
| `--json file.json` | Saves the results. Needed for `compare.py`. |
| `--pdf file.pdf` | Saves the PDF report. |
| `--only email,tls` | Runs only these checks. Names: `email`, `tls`, `headers`, `ports`, `paths`, `lookalike`. |
| `--own other.com,other.ng` | Domains the business owns. They are not reported as lookalikes. |

The options `--dns`, `--https-port`, `--http-port` and `--ca-file` exist only for the demo shop below.

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

## Try it without a real business

`lab/` holds a made-up shop called Demo Shop. It has a small web server and a small DNS server with deliberate weaknesses. It also has the same shop after the fixes. Nothing in it is real.

Use Option A (Python) for the demo. Run these from the `securecheck` folder:

```
sh lab/make_certs.sh
echo "127.0.0.1 demo-shop.test" | sudo tee -a /etc/hosts
sh lab/demo.sh "Your Name"
```

The demo scans the shop before the fixes, applies them, scans again, and prints the comparison. It writes `before.pdf`, `after.pdf`, `before.json` and `after.json`. The comparison ends with `Problems: 14 before -> 0 after`.

This is a demonstration of the tool and the report. It is not a result from a real business.

## Run the tests

```
python3 -m pytest -q
```

The tests use local servers and a test certificate. They need the `openssl` command line tool.

## How it was checked

Results were compared with other tools:

- Email results against `dig`.
- Certificate, HSTS, redirect and old-TLS results against `curl` and `openssl s_client`.
- Header results against `curl`.
- Port results against `ss -tln` on a lab machine.
- The Docker build gave the same findings as a direct run.

One mismatch came up: `curl -I` (HEAD) showed a different Server header than a GET request. The server answers the two differently. SecureCheck uses GET, which is what browsers send.

## Limits

- It is an outside-in check of public information. It is not a penetration test.
- It never logs in, guesses passwords or looks at customer data.
- DKIM selectors are private names. "Not found" means not found among common names.
- Only the home page is requested for header checks. Other pages may differ.
- Port results depend on the network you scan from. "Filtered" is not the same as closed. On shared hosting the ports belong to the host's server.
- If a network accepts connections on ports that should be closed, the port check refuses to report. Some home networks do this. Use another network, such as a phone hotspot.
- The old-TLS test depends on the machine being able to attempt old protocols. A failed attempt does not prove the server refuses them.
- The exposed-file check looks at six addresses. A clean result does not mean nothing is exposed.
- A registered lookalike is not proof of abuse. It may belong to the owner. Only likely variants are tested.
- If a network's DNS answers for names that do not exist, the lookalike check refuses to report.
- A slow network can stop a check. That is reported as "could not complete", not as a problem with the website.

## Ethics

Only check domains you own or have written permission to check. The tool sends a small number of normal requests. It does not try to break in or slow a site down. Files found by the exposed-file check are never saved. The report says only that they were readable.

## Not built yet

- A web page where a business owner can type a domain and get the report without help.
- A staff awareness exercise. Volunteers who agreed in advance would get a safe link, and the report would count who opened it.
