# security-headers-check

Audit HTTP security response headers **offline**, in CI. Save a header
dump from a deploy (`curl -sS -D headers.txt -o /dev/null https://your.site`
or a copy from browser devtools) and check it against the OWASP Secure
Headers Project's recommended set:

```sh
python3 security_headers_check.py headers.txt
```

```
headers.txt [warning] hsts-missing: Strict-Transport-Security missing: browsers will keep allowing plain-HTTP access; OSHP recommends max-age=63072000; includeSubDomains ...
headers.txt [warning] info-leak-header: server: nginx/1.24.0 - on the OWASP Secure Headers Project removal list ...
security-headers-check: 0 error(s), 2 warning(s)
```

## What it checks

**Missing (warning each):** Strict-Transport-Security,
Content-Security-Policy, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy. X-Frame-Options is flagged only when the CSP has no
`frame-ancestors` directive, because OSHP documents that
`frame-ancestors` obsoletes X-Frame-Options.

**Value problems:**
- `x-content-type-options-wrong` (error) - the only defined value is `nosniff`.
- `hsts-no-max-age` (error) - RFC 6797 makes `max-age` REQUIRED.
- `hsts-max-age-zero` (warning) - RFC 6797: `max-age=0` removes the policy.
- `hsts-max-age-below-recommended` (warning) - below OSHP's recommended `63072000`.
- `hsts-no-include-subdomains` (warning) - OSHP's recommended value includes it.
- `x-frame-options-invalid` (error) - only `deny` / `sameorigin` are supported (`allow-from` is not, in modern browsers).
- `csp-wildcard` (error, heuristic) - `default-src *` or `script-src *`.
- `csp-unsafe-inline` / `csp-unsafe-eval` (warning, heuristic) - not in OSHP's recommended policy.

**Exposure (warning each):** any header on the OSHP removal list
(`Server`, `X-Powered-By`, `X-AspNet-Version`, 87 entries - platform
fingerprinting), and headers OSHP lists as deprecated
(`X-XSS-Protection`, `Public-Key-Pins`, `Expect-CT`, `Feature-Policy`,
`Pragma`).

## CLI

```sh
python3 security_headers_check.py dump1.txt dump2.txt
python3 security_headers_check.py --ignore hsts-no-include-subdomains dump.txt
python3 security_headers_check.py --format json --fail-on-warning dump.txt
```

Exit `0` clean, `1` on errors (or warnings with `--fail-on-warning`),
`2` on unreadable input. With redirects in one dump (`curl -i -L`), the
**last** response is audited. Zero dependencies, no network calls; CI
runs on Ubuntu and Windows, Python 3.9 and 3.13.

## The data

`headers.json` ships the OWASP Secure Headers Project's machine-readable
lists verbatim: the 13 recommended headers with values and the
87-entry removal list (data files last updated by OSHP 2026-10-18,
fetched here 2026-11-01). Heuristic rules (`csp-wildcard`,
`csp-unsafe-*`) are labeled as heuristics in their messages. The tool
audits one response's header set; it does not judge per-route
differences (e.g. `Clear-Site-Data`, which belongs on logout endpoints
only, is intentionally not required).

## Compared to

- [securityheaders.com](https://securityheaders.com) - the well-known
  online scanner: grades a live public URL from their service. This
  repo is the offline complement: no site exposed to a third party, no
  network at scan time, dump-based and CI-gated with exit codes, and
  every rule traces to the OSHP data files or RFC 6797.

## Sources

- [OWASP Secure Headers Project](https://github.com/OWASP/secure-headers-project) -
  `ci/headers_add.json`, `ci/headers_remove.json` (recommended and
  removal lists), `mainsite/01_headers.md` (header reference, deprecated
  list, frame-ancestors/XFO relationship, XFO and X-Content-Type-Options
  values).
- [RFC 6797 - HTTP Strict Transport Security](https://www.rfc-editor.org/rfc/rfc6797) -
  `max-age` REQUIRED; `max-age=0` removes the policy.

## License

MIT
