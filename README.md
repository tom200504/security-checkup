# Security Checkup

Small command-line security checks written in Python. A web dashboard is planned.

## Modules

- **password**: checks whether a password appears in known data leaks, without ever sending it.
- **email**: checks the email protections of a domain (SPF, DMARC, DKIM).

## Install

```
git clone https://github.com/tom200504/security-checkup.git
cd security-checkup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```
python3 cli.py password
python3 cli.py email example.com
python3 cli.py email example.com --selector myselector
```

## Security choices

- **Password**: typed with `getpass` (hidden). The SHA-1 hash is computed locally and only its first 5 characters are sent to the Pwned Passwords API (k-anonymity). The rest of the hash is compared locally, so the service never sees the password or the full hash. Nothing is stored or logged.
- **Email**: the domain and the DKIM selector are validated with an allow-list (regex) before any DNS query. Queries are read-only. "No record found" is distinguished from "DNS failure", so a network problem is never reported as a missing protection.
- Network calls have a timeout and error messages stay generic (no internal details).

## Verdict rules

- **Password**: 0 occurrences = OK, 1 to 99 = ATTENTION, 100 or more = RISK. (Explain here why you chose these thresholds.)
- **Email**: the overall level is the worst of SPF and DMARC. DKIM is informational only.
  - SPF: none = RISK, several records = ATTENTION, `-all` or `~all` = OK, `+all` = RISK.
  - DMARC: none = RISK, `p=none` = ATTENTION, `quarantine` or `reject` = OK.
  - `~all` counts as OK because it is common and acceptable when DMARC is enforced.

## Limitations

- A password absent from leaks is not necessarily strong.
- The password module depends on a third-party service.
- DKIM cannot be discovered without its selector: the tool tries common ones, and "not detected" does not mean "absent".
- SPF `redirect=` and `include:` are not followed.
- DMARC subdomain policy (`sp=`) is ignored.
- Domains with accents (internationalized names) are rejected.

## Roadmap

- Web dashboard (one page, one backend route per module).
- More modules (suspicious link, suspicious document).

## Credits

Pwned Passwords API by Have I Been Pwned (Troy Hunt).