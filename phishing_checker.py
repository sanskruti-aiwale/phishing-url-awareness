"""EWB Phishing URL Awareness Checker.

An educational, text-only tool. It reads a URL as plain text and points out
a few visible warning signs. It NEVER opens a URL, never uses the network
and never stores or sends what you type.

"No warning signs found" does NOT mean a URL is safe.
"""

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

# ---- Settings (change them here, not deep inside the code) -----------------
LONG_URL_LIMIT = 100       # URLs longer than this are flagged
MANY_SEGMENTS = 5          # hostnames with this many parts or more are flagged
QUIT_WORDS = ("q", "quit", "exit")
SAFETY_REMINDER = "Never enter passwords from unexpected links."


@dataclass(frozen=True)
class Finding:
    """One result line: what we found, why it matters, and its type."""

    message: str
    reason: str = ""
    is_warning: bool = True   # False for info messages like "No URL entered."


def _info(message):
    """Build an information-only finding (not a warning sign)."""
    return Finding(message=message, is_warning=False)


def analyze_url(raw_url):
    """Check visible URL text and return a list of Finding objects."""
    url = raw_url.strip()
    if not url:
        return [_info("No URL entered.")]

    # If the scheme is missing, add one so urlparse can find the hostname.
    candidate = url if "://" in url else "http://" + url

    # Improvement C: malformed text such as "http://[bad" must never crash us.
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return [_info("This text is not a valid URL format.")]

    if not host:
        return [_info("Could not identify a hostname.")]

    findings = []

    # Check 1: @ symbol
    if "@" in candidate:
        findings.append(Finding(
            "Contains an @ symbol; inspect carefully.",
            "Browsers ignore the text before @, so a link can look like "
            "one site but lead to another."))

    # Check 2: very long URL
    if len(url) > LONG_URL_LIMIT:
        findings.append(Finding(
            "Unusually long URL (over 100 characters).",
            "Long links can hide the real destination far to the right."))

    # Check 3: IP address as hostname
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        findings.append(Finding(
            "Uses an IP address instead of a familiar domain.",
            "Honest services normally use readable names; a bare number "
            "hides who owns the site."))

    # Check 4: many hostname segments
    labels = [part for part in host.split(".") if part]
    if len(labels) >= MANY_SEGMENTS:
        findings.append(Finding(
            "Contains many hostname segments/subdomains.",
            "Stacking names like a.b.c.d.e can make a link look official."))

    # Check 5: punycode marker
    if "xn--" in host:
        findings.append(Finding(
            "Contains a punycode-style hostname.",
            "Punycode can hide look-alike foreign letters that mimic "
            "real names."))

    # Check 6: plain HTTP
    if parsed.scheme.lower() == "http":
        findings.append(Finding(
            "Uses HTTP. HTTPS alone does not prove trust.",
            "HTTP is not encrypted, so data can be seen on the way. "
            "(And HTTPS alone does not prove a site is honest.)"))

    if not findings:
        findings.append(Finding(
            "No listed warning signs found. This does NOT prove safety.",
            "This tool checks only six clues. A dangerous link can have none "
            "of them.",
            is_warning=False))
    return findings


def inspect_url(raw_url):
    """Workbook-style helper: return just the message strings."""
    return [item.message for item in analyze_url(raw_url)]


def has_warnings(findings):
    """True if at least one finding is a real warning sign."""
    return any(item.is_warning for item in findings)


def count_warnings(findings):
    """How many real warning signs were found."""
    return sum(1 for item in findings if item.is_warning)


def print_report(raw_url):
    """Improvements B, D and E: numbered, explained, summarised output."""
    findings = analyze_url(raw_url)
    print("\nResult:")
    for number, item in enumerate(findings, start=1):
        print(f"- {item.message}")
        if item.reason:
            print(f"    Why it matters: {item.reason}")
    if has_warnings(findings):
        print(f"\nREVIEW CAREFULLY: {count_warnings(findings)} "
              "warning sign(s) found. These are clues, not proof.")
    print(SAFETY_REMINDER)


def run_interactive():
    """Improvement A: keep checking URLs until the user quits."""
    print("EWB Phishing URL Awareness Checker")
    print("Text checks only - this program does not open URLs.")
    while True:
        try:
            raw_url = input("\nEnter a sample URL (or type q to quit): ")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye! Stay alert online.")
            return 0
        if raw_url.strip().lower() in QUIT_WORDS:
            print("Goodbye! Stay alert online.")
            return 0
        print_report(raw_url)


def run_batch(path, as_json):
    """Check every line of a text file of SAMPLE URLs (text only)."""
    try:
        with open(path, encoding="utf-8") as handle:
            lines = [ln.strip() for ln in handle]
    except OSError as error:
        print(f"Could not read file: {error}", file=sys.stderr)
        return 2
    urls = [ln for ln in lines if ln and not ln.startswith("#")]

    if as_json:
        report = [{"input": u,
                   "warning_signs": count_warnings(analyze_url(u)),
                   "findings": [asdict(f) for f in analyze_url(u)]}
                  for u in urls]
        print(json.dumps(report, indent=2))
    else:
        for url in urls:
            print(f"\n{url}")
            for item in analyze_url(url):
                print(f"  - {item.message}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Text-only phishing URL awareness checker. "
                    "It never opens URLs.")
    parser.add_argument("--file", help="text file with one sample URL per line")
    parser.add_argument("--json", action="store_true",
                        help="with --file: print results as JSON")
    args = parser.parse_args(argv)
    if args.file:
        return run_batch(args.file, args.json)
    return run_interactive()


if __name__ == "__main__":
    sys.exit(main())
