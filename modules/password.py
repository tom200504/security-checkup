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


def check_password():
    password = getpass.getpass("enter password : ")
    if password == "":
        print("The password can't be empty")
        return False
    octect = password.encode("utf-8")
    password_hash = hashlib.sha1(octect)
    password_hashfinal = password_hash.hexdigest().upper()
    prefix = password_hashfinal[:5]
    sufix = password_hashfinal[5:]

    URL = "https://api.pwnedpasswords.com/range/" + prefix
    try:
        response = requests.get(URL, timeout=5)
    except requests.RequestException:
        print("Unable to reach the service, try again later.")
        return False
    if response.status_code != 200:
        print("error in status code of the call API")
        return False
    lines = response.text.splitlines()
    count = 0
    for raw_line in lines:
        parts = raw_line.split(":")
        if parts[0] == sufix:
            count = int(parts[1])
            break

    level, message = evaluate(count)
    return {"count": count, "level": level, "message": message}


if __name__ == "__main__":
    result = check_password()
    if result:
        print(result["level"] + ": " + result["message"])
        print("Seen " + str(result["count"]) + " times in known leaks.")