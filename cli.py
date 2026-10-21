import argparse
from modules.password import check_password
from modules.email_domain import check_email_domain

parser = argparse.ArgumentParser(description="Security Checkup: small security checks")
sub = parser.add_subparsers(dest="command", required=True)

sub.add_parser("password", help="check if a password appears in known leaks")

email_parser = sub.add_parser("email", help="check the email protections of a domain (SPF, DMARC, DKIM)")
email_parser.add_argument("domain", help="domain to check, for example example.com")
email_parser.add_argument("--selector", help="DKIM selector, if you know it (the s= value in a mail header)")

args = parser.parse_args()

if args.command == "password":
    result = check_password()
    if result:
        print(result["level"] + ": " + result["message"])
        print("Seen " + str(result["count"]) + " times in known leaks.")
elif args.command == "email":
    result = check_email_domain(args.domain, args.selector)
    if result:
        print("Overall: " + result["overall"])
        for name in ("spf", "dmarc", "dkim"):
            level, message = result[name]
            print(name.upper() + " [" + level + "]: " + message)