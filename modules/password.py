import getpass
import hashlib
import requests

# Thresholds: number of times a password appears in known leaks
ATTENTION_THRESHOLD = 1    # from 1 occurrence: ATTENTION
RISK_THRESHOLD = 100       # from 100 occurrences: RISK


def evaluate(count):
    """Turn a number of occurrences into a (level, explanation) verdict."""
    if count >= RISK_THRESHOLD:
        return "RISK", "This password is very widespread in leaks: attackers try it first. Change it everywhere you use it."
    if count >= ATTENTION_THRESHOLD:
        return "ATTENTION", "This password appears in known leaks. Change it, even if it is rare."
    return "OK", "Not found in known leaks. This does not mean it is strong: a short or predictable password can simply not have leaked yet."


def hash_password(password):
    """Return the SHA-1 hash of a password, as uppercase hexadecimal text."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def count_leaks(password_hash):
    """Return how many times a SHA-1 hash appears in known leaks.
    Only the first 5 characters of the hash are sent (k-anonymity).
    Returns None if the service can't be queried."""
    prefix = password_hash[:5]
    suffix = password_hash[5:]
    try:
        response = requests.get("https://api.pwnedpasswords.com/range/" + prefix, timeout=5)
    except requests.RequestException:
        return None
    if response.status_code != 200:
        return None
    for raw_line in response.text.splitlines():
        parts = raw_line.split(":")
        if parts[0] == suffix:
            return int(parts[1])
    return 0


def check_password():
    """Command-line flow: ask for a password, then return the verdict."""
    password = getpass.getpass("enter password : ")
    if password == "":
        print("The password can't be empty")
        return False
    count = count_leaks(hash_password(password))
    if count is None:
        print("Unable to reach the service, try again later.")
        return False
    level, message = evaluate(count)
    return {"count": count, "level": level, "message": message}