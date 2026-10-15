import argparse
import getpass
import sys

from .hibp import check


def describe(count: int) -> str:
    if count == 0:
        return "not found in any known breach"
    return f"FOUND {count:,} times in breach data. Don't use it."


def label(line_no: int, pw: str) -> str:
    # Even a partial mask like "pa*****" narrows down a password, so by default show only where it is.
    return f"line {line_no} ({len(pw)} characters)"


def main() -> None:
    p = argparse.ArgumentParser(
        prog="breach_check",
        description="Check passwords against Have I Been Pwned without sending them anywhere.",
        epilog="The password is never accepted as a command-line argument: those end up in shell history.",
    )
    p.add_argument("--file", help="check every password in a file (one per line), e.g. passwords seen by a honeypot")
    p.add_argument("--show", action="store_true",
                   help="with --file, print the passwords themselves (default: only line number and length)")
    args = p.parse_args()

    if args.file:
        entries: dict[str, int] = {}
        with open(args.file, encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                pw = line.rstrip("\r\n")
                if pw.strip() and pw not in entries:
                    entries[pw] = line_no
        found = 0
        for pw, line_no in entries.items():
            result = check(pw)
            found += result["breach_count"] > 0
            shown = pw if args.show else label(line_no, pw)
            print(f"{result['breach_count']:>12,}  {shown}")
        print(f"\n{found} of {len(entries)} passwords appear in known breaches.")
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
