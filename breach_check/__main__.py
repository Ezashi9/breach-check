import argparse
import getpass
import sys

from .hibp import check


def describe(count: int) -> str:
    if count == 0:
        return "not found in any known breach"
    return f"FOUND {count:,} times in breach data. Don't use it."


def mask(pw: str) -> str:
    return pw[:2] + "*" * max(len(pw) - 2, 0) if len(pw) > 2 else "*" * len(pw)


def main() -> None:
    p = argparse.ArgumentParser(
        prog="breach_check",
        description="Check passwords against Have I Been Pwned without sending them anywhere.",
        epilog="The password is never accepted as a command-line argument: those end up in shell history.",
    )
    p.add_argument("--file", help="check every password in a file (one per line), e.g. passwords seen by a honeypot")
    p.add_argument("--show", action="store_true", help="with --file, print passwords in full instead of masked")
    args = p.parse_args()

    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as f:
            passwords = list(dict.fromkeys(line.rstrip("\r\n") for line in f if line.strip()))
        found = 0
        for pw in passwords:
            result = check(pw)
            found += result["breach_count"] > 0
            shown = pw if args.show else mask(pw)
            print(f"{result['breach_count']:>12,}  {shown}")
        print(f"\n{found} of {len(passwords)} passwords appear in known breaches.")
        return

    pw = getpass.getpass("Password to check (input hidden): ")
    if not pw:
        sys.exit("No password entered.")
    result = check(pw)
    print(f"Sent to the API: {result['prefix_sent']} (first 5 of 40 hash characters)")
    print(f"Your hash was compared locally against {result['hashes_returned']:,} returned hashes.")
    print(describe(result["breach_count"]))


if __name__ == "__main__":
    main()
