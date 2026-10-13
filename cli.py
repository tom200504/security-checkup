import argparse
from modules.password import check_password

parser = argparse.ArgumentParser(description="Security Checkup: small security checks")
sub = parser.add_subparsers(dest="command", required=True)
sub.add_parser("password", help="check if a password appears in known leaks")

args = parser.parse_args()

if args.command == "password":
    result = check_password()
    if result:
        print(result["level"] + ": " + result["message"])
        print("Seen " + str(result["count"]) + " times in known leaks.")