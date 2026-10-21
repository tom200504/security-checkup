import re
import dns.resolver
import dns.exception

DOMAIN_RE = r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"


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


def check_email_domain(domain):
    domain = domain.strip().lower()
    if not re.match(DOMAIN_RE, domain):
        print("Invalid domain name.")
        return False

    records = get_txt_records(domain)
    if records is None:
        print("Unable to query the DNS, try again later.")
        return False

    spf_records = []
    for record in records:
        if record.startswith("v=spf1"):
            spf_records.append(record)
    print(spf_records)  # temporary

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
    print(dmarc_policy)  # temporary


if __name__ == "__main__":
    check_email_domain(input("Domain: "))