"""Automated tests. Run from the project root:
    python -m unittest discover -s tests -v      (Mac/Linux: python3)
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import phishing_checker as pc  # noqa: E402

NO_SIGNS = "No listed warning signs found. This does NOT prove safety."
IP = "Uses an IP address instead of a familiar domain."
HTTP = "Uses HTTP. HTTPS alone does not prove trust."
AT = "Contains an @ symbol; inspect carefully."
MANY = "Contains many hostname segments/subdomains."
PUNY = "Contains a punycode-style hostname."
LONG = "Unusually long URL (over 100 characters)."


class WorkbookSamples(unittest.TestCase):
    """The five official samples from Section 08."""

    def test_1_clean(self):
        self.assertEqual(pc.inspect_url("https://www.example.com/login"), [NO_SIGNS])

    def test_2_ip_and_http(self):
        self.assertEqual(pc.inspect_url("http://192.0.2.10/account"), [IP, HTTP])

    def test_3_at_and_http(self):
        self.assertEqual(
            pc.inspect_url("http://example.com@sample.invalid/login"), [AT, HTTP])

    def test_4_many_segments(self):
        self.assertEqual(
            pc.inspect_url("https://a.b.c.d.e.example.invalid/path"), [MANY])

    def test_5_punycode(self):
        self.assertEqual(pc.inspect_url("https://xn--example.invalid/"), [PUNY])


class EdgeCases(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(pc.inspect_url(""), ["No URL entered."])

    def test_spaces_only(self):
        self.assertEqual(pc.inspect_url("   "), ["No URL entered."])

    def test_missing_scheme_is_treated_as_http(self):
        self.assertEqual(pc.inspect_url("www.example.com"), [HTTP])

    def test_tricky_name_slips_through(self):
        self.assertEqual(
            pc.inspect_url("https://secure-login.example.invalid"), [NO_SIGNS])

    def test_malformed_does_not_crash(self):
        self.assertEqual(pc.inspect_url("http://[bad"),
                         ["This text is not a valid URL format."])

    def test_no_hostname(self):
        self.assertEqual(pc.inspect_url("http://"),
                         ["Could not identify a hostname."])

    def test_long_url(self):
        url = "https://www.example.com/" + "a" * 100
        self.assertIn(LONG, pc.inspect_url(url))

    def test_exactly_100_chars_is_not_long(self):
        prefix = "https://www.example.com/"
        url = prefix + "a" * (100 - len(prefix))
        self.assertEqual(len(url), 100)
        self.assertNotIn(LONG, pc.inspect_url(url))

    def test_four_segments_not_flagged(self):
        self.assertNotIn(MANY, pc.inspect_url("https://a.b.example.invalid/"))

    def test_uppercase_scheme_and_host(self):
        self.assertEqual(pc.inspect_url("HTTP://192.0.2.10/"), [IP, HTTP])

    def test_every_warning_has_a_reason(self):
        for url in ("http://192.0.2.10/", "http://a@b.invalid", "https://xn--e.invalid"):
            for f in pc.analyze_url(url):
                if f.is_warning:
                    self.assertTrue(f.reason)

    def test_info_messages_are_not_warnings(self):
        for text in ("", "http://[bad", "https://www.example.com/login"):
            self.assertFalse(pc.has_warnings(pc.analyze_url(text)))


class OutputAndModes(unittest.TestCase):
    def run_main(self, argv=None, inputs=()):
        out = io.StringIO()
        with mock.patch("builtins.input", side_effect=list(inputs)), \
                contextlib.redirect_stdout(out):
            code = pc.main(argv or [])
        return code, out.getvalue()

    def test_loop_quits_and_summarises(self):
        code, out = self.run_main(inputs=["http://192.0.2.10/account", "q"])
        self.assertEqual(code, 0)
        self.assertIn("REVIEW CAREFULLY: 2 warning sign(s) found.", out)
        self.assertIn("Goodbye!", out)

    def test_no_summary_when_clean(self):
        _, out = self.run_main(inputs=["https://www.example.com/login", "quit"])
        self.assertNotIn("REVIEW CAREFULLY", out)

    def test_batch_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                         encoding="utf-8") as tmp:
            tmp.write("# comment\nhttp://192.0.2.10/account\n\nhttps://xn--example.invalid/\n")
        try:
            code, out = self.run_main(["--file", tmp.name, "--json"])
        finally:
            os.unlink(tmp.name)
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["warning_signs"], 2)

    def test_batch_missing_file(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = pc.main(["--file", "does-not-exist.txt"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
