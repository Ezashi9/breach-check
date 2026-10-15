import hashlib
import urllib.request
from typing import Callable

RANGE_URL = "https://api.pwnedpasswords.com/range/"
PREFIX_LEN = 5

Fetcher = Callable[[str], str]


def _http_fetch(prefix: str) -> str:
    # Add-Padding makes the service add fake zero-count entries so the response size
    # can't hint at which prefix (and so which password) was looked up.
    req = urllib.request.Request(
        RANGE_URL + prefix,
        headers={"Add-Padding": "true", "User-Agent": "breach-check (github.com/Ezashi9/breach-check)"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8")


def split_hash(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:PREFIX_LEN], digest[PREFIX_LEN:]


def parse_range(body: str) -> dict[str, int]:
    counts = {}
    for line in body.splitlines():
        suffix, _, count = line.strip().partition(":")
        if suffix and count.isdigit() and int(count) > 0:
            counts[suffix.upper()] = int(count)
    return counts


def check(password: str, fetch: Fetcher = _http_fetch) -> dict:
    """Return how many times the password appears in known breaches, sending only 5 hash characters."""
    prefix, suffix = split_hash(password)
    body = fetch(prefix)
    returned = [line for line in body.splitlines() if line.strip()]
    return {
        "breach_count": parse_range(body).get(suffix, 0),
        "prefix_sent": prefix,
        "hashes_returned": len(returned),
    }
