import hashlib
import unittest

from breach_check.hibp import check, parse_range, split_hash

PASSWORD = "password123"
FULL = hashlib.sha1(PASSWORD.encode()).hexdigest().upper()


class FakeAPI:
    def __init__(self, body):
        self.body = body
        self.requests = []

    def __call__(self, prefix):
        self.requests.append(prefix)
        return self.body


class HibpTests(unittest.TestCase):
    def test_only_five_hash_characters_leave_the_machine(self):
        api = FakeAPI("")
        check(PASSWORD, fetch=api)
        self.assertEqual(api.requests, [FULL[:5]])
        self.assertNotIn(PASSWORD, api.requests[0])

    def test_found_password_returns_count(self):
        body = f"0000000000000000000000000000000000A:3\r\n{FULL[5:]}:2266543\r\n"
        result = check(PASSWORD, fetch=FakeAPI(body))
        self.assertEqual(result["breach_count"], 2266543)
        self.assertEqual(result["hashes_returned"], 2)

    def test_missing_password_returns_zero(self):
        result = check(PASSWORD, fetch=FakeAPI("0000000000000000000000000000000000A:3\n"))
        self.assertEqual(result["breach_count"], 0)

    def test_padding_entries_with_zero_count_are_ignored(self):
        self.assertEqual(parse_range(f"{FULL[5:]}:0\nABC:7"), {"ABC": 7})

    def test_hash_split(self):
        prefix, suffix = split_hash(PASSWORD)
        self.assertEqual(prefix + suffix, FULL)
        self.assertEqual(len(prefix), 5)

    def test_suffix_match_is_case_insensitive(self):
        result = check(PASSWORD, fetch=FakeAPI(f"{FULL[5:].lower()}:9"))
        self.assertEqual(result["breach_count"], 9)

    def test_unicode_passwords_hash_as_utf8(self):
        prefix, _ = split_hash("pässwörd")
        self.assertEqual(prefix, hashlib.sha1("pässwörd".encode("utf-8")).hexdigest().upper()[:5])


if __name__ == "__main__":
    unittest.main()
