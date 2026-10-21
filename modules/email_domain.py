import re
import dns.resolver
import dns.exception

DOMAIN_RE = r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
SELECTOR_RE = r"^[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?$"

DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "k1", "s1", "s2", "dkim"]

# Severity order: used to compute the overall level (the worst one wins)
LEVEL_ORDER = {"OK": 0, "ATTENTION": 1, "RISK": 2}


def get_txt_records(name):
    """Return the TXT records of a DNS name as a list of strings.
    Empty list: no record (or the name doesn't exist).
    None: technical problem (timeout, no network)."""
    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=5)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return None
    records = []
    for rdata in answer:
        text = "".join(part.decode("utf-8", errors="replace") for part in rdata.strings)
        records.append(text)
    return records


def evaluate_spf(spf_records):
    """Turn the SPF records found into a (level, message) verdict."""
    if len(spf_records) == 0:
        return "RISK", "No SPF record: nothing says which servers may send mail for this domain."
    if len(spf_records) > 1:
        return "ATTENTION", "Several SPF records: this is a configuration error, receivers may ignore them."
    tokens = spf_records[0].split()
    ending = tokens[-1].lower()
    if ending in ("-all", "~all"):
        return "OK", "SPF found, other servers are refused or treated as suspicious (" + ending + ")."
    if ending in ("+all", "all"):
        return "RISK", "SPF authorizes every server to send mail for this domain (" + ending + ")."
    return "ATTENTION", "SPF found, but its ending rule is unclear or neutral."


def evaluate_dmarc(policy):
    """Turn the DMARC policy (or None) into a (level, message) verdict."""
    if policy is None:
        return "RISK", "No DMARC policy: receivers get no instruction when SPF or DKIM fail."
    if policy in ("quarantine", "reject"):
        return "OK", "DMARC policy is enforced (p=" + policy + ")."
    if policy == "none":
        return "ATTENTION", "DMARC only monitors (p=none): spoofed mails are not blocked."
    return "ATTENTION", "Unrecognised DMARC policy (p=" + policy + ")."


def evaluate_dkim(dkim_selector):
    """DKIM is informational only: it never changes the overall level."""
    if dkim_selector is not None:
        return "INFO", "DKIM detected (selector: " + dkim_selector + ")."
    return "INFO", "DKIM not detected among the tested selectors. This does not mean it is absent."


def check_email_domain(domain, selector=None):
    domain = domain.strip().lower()
    if not re.match(DOMAIN_RE, domain):
        print("Invalid domain name.")
        return False

    if selector is not None:
        selector = selector.strip().lower()
        if not re.match(SELECTOR_RE, selector):
            print("Invalid selector.")
            return False
        selectors_to_test = [selector]
    else:
        selectors_to_test = DKIM_SELECTORS

    records = get_txt_records(domain)
    if records is None:
        print("Unable to query the DNS, try again later.")
        return False

    spf_records = []
    for record in records:
        if record.startswith("v=spf1"):
            spf_records.append(record)

    dmarc_txt = get_txt_records("_dmarc." + domain)
    if dmarc_txt is None:
        print("Unable to query the DNS, try again later.")
        return False

    dmarc_policy = None
    for record in dmarc_txt:
        if record.lower().startswith("v=dmarc1"):
            for part in record.split(";"):
                part = part.strip()
                if part.lower().startswith("p="):
                    dmarc_policy = part[2:].lower()

    dkim_selector = None
    for candidate in selectors_to_test:
        dkim_txt = get_txt_records(candidate + "._domainkey." + domain)
        if dkim_txt is None:
            print("Unable to query the DNS, try again later.")
            return False
        for record in dkim_txt:
            if record.lower().startswith("v=dkim1"):
                dkim_selector = candidate
        if dkim_selector is not None:
            break

    spf = evaluate_spf(spf_records)
    dmarc = evaluate_dmarc(dmarc_policy)
    dkim = evaluate_dkim(dkim_selector)

    # SPF and DMARC decide the overall level, DKIM only informs
    overall = spf[0]
    if LEVEL_ORDER[dmarc[0]] > LEVEL_ORDER[overall]:
        overall = dmarc[0]

    return {"domain": domain, "overall": overall, "spf": spf, "dmarc": dmarc, "dkim": dkim}


if __name__ == "__main__":
    domain = input("Domain: ")
    selector = input("DKIM selector (Enter to skip): ").strip() or None
    result = check_email_domain(domain, selector)
    if result:
        print("Overall: " + result["overall"])
        for name in ("spf", "dmarc", "dkim"):
            level, message = result[name]
            print(name.upper() + " [" + level + "]: " + message)