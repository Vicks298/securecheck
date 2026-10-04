import sys, json
from checks.email_check import check_email

if __name__ == "__main__":
    for f in check_email(sys.argv[1]):
        print(f"[{f.severity}] {f.title}")
        print(f"   {f.detail}")
        print(f"   Fix: {f.fix}\n")
