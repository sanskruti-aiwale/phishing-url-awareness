# Test Results

Python version used: 3.14.0 | Operating system: 
Windows | Date: 29/10/2026

> Re-run each sample on YOUR computer and copy what YOUR screen shows.
> The "Actual result" column below is the reference output; replace it with
> your own if anything differs, and mark PASS or FAIL honestly.

| # | Input | Expected result | Actual result | Pass/Fail |
|---|-------|-----------------|---------------|-----------|
| 1 | https://www.example.com/login | No listed warning signs | No listed warning signs found. This does NOT prove safety. | PASS |
| 2 | http://192.0.2.10/account | IP address + HTTP | Uses an IP address instead of a familiar domain. / Uses HTTP. HTTPS alone does not prove trust. |PASS |
| 3 | http://example.com@sample.invalid/login | @ symbol + HTTP | Contains an @ symbol; inspect carefully. / Uses HTTP. HTTPS alone does not prove trust. |PASS |
| 4 | https://a.b.c.d.e.example.invalid/path | Many hostname segments | Contains many hostname segments/subdomains. |PASS |
| 5 | https://xn--example.invalid/ | Punycode-style hostname | Contains a punycode-style hostname. |PASS |

## Bonus checks

| Input | Result |
|-------|--------|
| (empty) | No URL entered. |
| www.example.com | Uses HTTP. HTTPS alone does not prove trust. |
| https://secure-login.example.invalid | No listed warning signs found. (A tricky name slipped through.) |
| http://[bad | This text is not a valid URL format. (no crash) |

## Notes

Write 2 or 3 lines in your own words: what you learned, and what surprised you.
1. I learned that the program only reads the text of a URL and never opens it.
2. The link https://www.example.com/login showed no warnings, but the program says that does not mean it is safe.
3. I was surprised that http://example.com@sample.invalid/login looks like example.com but really goes to sample.invalid.