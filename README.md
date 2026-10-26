# secscan2026

A small, dependency-free security scanner for the kinds of flaws that dominated 2026:
leaked secrets, Supabase/RLS misconfig, wildcard CORS, committed `.env`, debug mode,
SQL built by string concatenation, path traversal, insecure deserialization, and
out-of-date runtimes affected by recent CVEs.

It runs in **two modes**:

```bash
# 1) Scan a local project folder or a single file (static + dependency checks)
secscan path ./my-project
secscan path ./my-project/app.py

# 2) Passively scan a domain you OWN (read-only, requires explicit consent)
secscan url https://my-site.example --i-own-this
```

Both modes write `secscan-report.md` and `secscan-report.json` (override with `-o`).

## What it is — and what it is not

**It is** a fast, heuristic (regex + version) scanner you can drop into a repo, a
pre-commit hook, or CI. It exits non-zero when it finds anything critical/high.

**It is not** an exploit tool. By design it has **no attack/exploit module**. The
`url` mode only reads what a browser already receives — no payloads, no fuzzing,
no auth bypass, no CVE exploitation, no writes — and refuses to run without
`--i-own-this`. Scanning systems you do not own or have permission to test may be
illegal.

It is also **not a replacement** for a full review. For real coverage pair it with
Semgrep, pip-audit, npm audit, osv-scanner and OWASP ZAP.

## Checks

### `path` mode — static analysis
- Hardcoded secrets (AWS, GitHub, OpenAI, Anthropic, Stripe, Google, Slack, SendGrid, Supabase `service_role`, private keys, JWTs, DB URLs) — CWE-798
- Generic high-entropy secret assignments — CWE-798
- Committed `.env` (not `.env.example`) — CWE-538
- Wildcard / reflected CORS — CWE-942
- Debug mode enabled — CWE-489
- Supabase `service_role` in code — CWE-522
- SQL by concatenation / f-string / `%` / `.format` — CWE-89
- Path traversal sinks — CWE-22
- Insecure deserialization (`pickle`, `yaml.load`) — CWE-502
- Dynamic `eval`/`exec` on user input — CWE-95
- `shell=True` / `os.system` with interpolation — CWE-78

Parameterized SQL (`execute("... %s", (x,))`) is **not** flagged.

### `path` mode — dependency / version checks
Parses `requirements.txt`, `package.json`, `composer.json`, `.python-version`,
`runtime.txt`, `.nvmrc`, and (unless `--no-runtime`) the local `python3`/`node`/
`php`/`nginx` versions, and flags versions at/below a known-vulnerable ceiling for
notable recent CVEs (PHP, NGINX, Node.js, CPython, PyYAML). This advisory list in
`secscan/cve_db.py` is **intentionally small and will go stale** — for authoritative
coverage, run a real SCA against OSV. Edit that file to add advisories.

### `url` mode — passive domain checks
Missing security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options,
Referrer-Policy); wildcard/reflected CORS; cookies missing Secure/HttpOnly/SameSite;
non-HTTPS; Supabase project references; and secrets found in **first-party** JS
bundles linked from the page.

## Install

```bash
git clone <your-repo-url>
cd secscan
pip install -e .        # installs the `secscan` command
# or run without installing:
python -m secscan path ./my-project
```

Python 3.9+. No third-party runtime dependencies.

## Use in CI

```yaml
# exits 1 if any critical/high finding is present
- run: python -m secscan path . -o secscan-report
```

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q
```

Tests run against deliberately vulnerable and deliberately clean fixtures in
`tests/`. The fixture `.env` contains fake, non-working values on purpose.

## License

MIT — see [LICENSE](LICENSE).

> Use responsibly and only on systems you own or are authorized to test.
