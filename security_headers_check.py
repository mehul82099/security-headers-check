#!/usr/bin/env python3
"""security-headers-check - audit HTTP security response headers, offline.

Point it at a saved header dump (`curl -sS -D dump.txt -o /dev/null URL`,
or a copy of the response headers from browser devtools) and it checks
the response against the OWASP Secure Headers Project's recommended set
and RFC 6797 (HSTS):

Missing (warning each): Strict-Transport-Security,
Content-Security-Policy, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy; X-Frame-Options only when CSP has no
frame-ancestors (OSHP: frame-ancestors obsoletes XFO).

Value problems: X-Content-Type-Options that is not `nosniff` (error);
HSTS without max-age (error - RFC 6797 makes it REQUIRED), max-age=0
(warning - clears the policy per RFC 6797), max-age below the OSHP
recommended 63072000 (warning), no includeSubDomains (warning);
X-Frame-Options outside deny/sameorigin (error); CSP wildcard sources
(error) and 'unsafe-inline'/'unsafe-eval' in script directives
(warning - both labeled heuristics).

Exposure: any header on the OSHP removal list (Server, X-Powered-By,
X-AspNet-Version, ... - warning), and headers OSHP lists as deprecated
(Feature-Policy, Expect-CT, Public-Key-Pins, X-XSS-Protection, Pragma -
warning).

The recommended values and removal list ship verbatim in headers.json
from the OWASP Secure Headers Project data files (see verified_at).

Pure standard library; no network at runtime.

Sources:
- https://github.com/OWASP/secure-headers-project (ci/headers_add.json,
  ci/headers_remove.json, mainsite/01_headers.md)
- https://www.rfc-editor.org/rfc/rfc6797
"""

import argparse
import json
import os
import re
import sys

HSTS_RECOMMENDED_MAX_AGE = 63072000  # OSHP recommended value

CORE_MISSING = [
    ("strict-transport-security", "hsts-missing",
     "Strict-Transport-Security missing: browsers will keep allowing "
     "plain-HTTP access; OSHP recommends max-age=63072000; "
     "includeSubDomains (relevant for HTTPS sites)."),
    ("content-security-policy", "csp-missing",
     "Content-Security-Policy missing: no defense-in-depth against "
     "XSS/data injection (OWASP Secure Headers Project)."),
    ("x-content-type-options", "x-content-type-options-missing",
     "X-Content-Type-Options missing; OSHP recommends `nosniff` to stop "
     "MIME sniffing away from the declared content-type."),
    ("referrer-policy", "referrer-policy-missing",
     "Referrer-Policy missing; OSHP recommends `no-referrer`."),
    ("permissions-policy", "permissions-policy-missing",
     "Permissions-Policy missing; OSHP recommends an explicit "
     "capability deny/allow list."),
]


class Finding:
    def __init__(self, path, rule, severity, message):
        self.path = path
        self.rule = rule
        self.severity = severity
        self.message = message

    def as_dict(self):
        return {
            "file": self.path,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
        }


def parse_dump(text):
    """Parse a header dump into the LAST response's headers.

    Splits on HTTP status lines so a `curl -i` capture with redirects
    yields one block per response; the final response is what the
    browser ends up on (documented convention). Returns a dict of
    lower-cased header name -> value (first occurrence wins).
    """
    blocks = []
    current = {}
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        if re.match(r"^HTTP/\S+\s+\d+", line.strip()):
            if current:
                blocks.append(current)
            current = {}
            continue
        m = re.match(r"^([A-Za-z0-9\-]+)\s*:\s*(.*)$", line)
        if m:
            name = m.group(1).lower()
            if name not in current:
                current[name] = m.group(2).strip()
    if current:
        blocks.append(current)
    return blocks[-1] if blocks else {}


def _hsts_max_age(value):
    m = re.search(r"(?:^|;)\s*max-age\s*=\s*\"?(\d+)\"?", value,
                  re.IGNORECASE)
    return int(m.group(1)) if m else None


def check_headers(headers, path):
    findings = []

    def emit(rule, severity, message):
        findings.append(Finding(path, rule, severity, message))

    present = set(headers)
    csp = headers.get("content-security-policy", "")
    csp_has_frame_ancestors = "frame-ancestors" in csp.lower()

    for name, rule, message in CORE_MISSING:
        if name not in present:
            emit(rule, "warning", message)
    if ("x-frame-options" not in present and not csp_has_frame_ancestors):
        emit("x-frame-options-missing", "warning",
             "X-Frame-Options missing and the CSP has no frame-ancestors "
             "directive: the page can be framed (clickjacking). OSHP "
             "recommends `X-Frame-Options: deny` or CSP frame-ancestors.")

    xcto = headers.get("x-content-type-options")
    if xcto is not None and xcto.lower() != "nosniff":
        emit("x-content-type-options-wrong", "error",
             "X-Content-Type-Options is `%s`; the only defined value is "
             "`nosniff` (OWASP Secure Headers Project)." % xcto)

    hsts = headers.get("strict-transport-security")
    if hsts is not None:
        max_age = _hsts_max_age(hsts)
        if max_age is None:
            emit("hsts-no-max-age", "error",
                 "Strict-Transport-Security has no max-age directive; "
                 "RFC 6797 makes max-age REQUIRED.")
        elif max_age == 0:
            emit("hsts-max-age-zero", "warning",
                 "Strict-Transport-Security max-age=0: RFC 6797 defines "
                 "this as removing the HSTS policy - intentional only "
                 "when rolling HSTS back.")
        elif max_age < HSTS_RECOMMENDED_MAX_AGE:
            emit("hsts-max-age-below-recommended", "warning",
                 "Strict-Transport-Security max-age=%d is below the "
                 "OWASP Secure Headers Project recommended value "
                 "63072000." % max_age)
        if "includesubdomains" not in hsts.lower():
            emit("hsts-no-include-subdomains", "warning",
                 "Strict-Transport-Security lacks includeSubDomains, "
                 "which the OSHP recommended value includes.")

    xfo = headers.get("x-frame-options")
    if xfo is not None and xfo.lower() not in ("deny", "sameorigin"):
        emit("x-frame-options-invalid", "error",
             "X-Frame-Options `%s` is not one of the supported values "
             "deny / sameorigin (allow-from is not supported by modern "
             "browsers)." % xfo)

    if csp:
        low = csp.lower()
        for directive in re.findall(r"([a-z-]+)\s+([^;]+)", low):
            name, value = directive
            if name in ("default-src", "script-src"):
                sources = value.split()
                if "*" in sources:
                    emit("csp-wildcard", "error",
                         "CSP %s allows any origin (*); heuristic: this "
                         "defeats the directive's protection." % name)
                for unsafe in ("'unsafe-inline'", "'unsafe-eval'"):
                    if unsafe in sources:
                        emit("csp-" + unsafe.strip("'"), "warning",
                             "CSP %s allows %s; heuristic: OSHP's "
                             "recommended policy does not include it." % (
                                 name, unsafe))

    return findings


def check_exposure(headers, path, data):
    findings = []
    leak = {n.lower() for n in data.get("info_leak", [])}
    deprecated = {n.lower() for n in data.get("deprecated", [])}
    for name, value in sorted(headers.items()):
        if name in leak:
            findings.append(Finding(
                path, "info-leak-header", "warning",
                "%s: %s - on the OWASP Secure Headers Project removal "
                "list; it discloses platform details an attacker can "
                "use for fingerprinting." % (name, value)))
        elif name in deprecated:
            findings.append(Finding(
                path, "deprecated-header", "warning",
                "%s is listed as deprecated by the OWASP Secure Headers "
                "Project; remove it." % name))
    return findings


def load_dataset(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def format_text(results):
    lines = []
    errors = warnings = 0
    for path, findings in results:
        for f in findings:
            lines.append("%s [%s] %s: %s" % (
                f.path, f.severity, f.rule, f.message))
            if f.severity == "error":
                errors += 1
            else:
                warnings += 1
    if errors or warnings:
        lines.append("security-headers-check: %d error(s), %d "
                     "warning(s)" % (errors, warnings))
    else:
        lines.append("security-headers-check: clean")
    return "\n".join(lines), errors, warnings


def build_parser():
    p = argparse.ArgumentParser(
        prog="security-headers-check",
        description="Audit HTTP security response headers from a saved "
                    "header dump, against the OWASP Secure Headers "
                    "Project and RFC 6797. Offline; no network calls.")
    p.add_argument("dumps", nargs="+",
                   help="header dump files (curl -D output or devtools "
                        "header copies)")
    p.add_argument("--data", metavar="JSON",
                   help="custom dataset instead of the bundled "
                        "headers.json")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE",
                   help="suppress a rule by name (repeatable)")
    p.add_argument("--fail-on-warning", action="store_true",
                   help="exit 1 when only warnings are present")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="output format (default: text)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    data_path = args.data or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "headers.json")
    try:
        data = load_dataset(data_path)
    except (OSError, ValueError) as exc:
        print("security-headers-check: cannot load dataset %s: %s" % (
            data_path, exc), file=sys.stderr)
        return 2
    ignore = set(args.ignore)
    results = []
    for path in args.dumps:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print("security-headers-check: cannot read %s: %s" % (
                path, exc), file=sys.stderr)
            return 2
        headers = parse_dump(text)
        if not headers:
            print("security-headers-check: no headers found in %s" %
                  path, file=sys.stderr)
            return 2
        findings = [f for f in (check_headers(headers, path) +
                                check_exposure(headers, path, data))
                    if f.rule not in ignore]
        results.append((path, findings))

    text_out, errors, warnings = format_text(results)
    if args.format == "json":
        print(json.dumps({
            "findings": [f.as_dict() for _, fs in results for f in fs],
            "summary": {"files": len(results), "errors": errors,
                        "warnings": warnings},
        }, indent=2))
    else:
        print(text_out)
    if errors:
        return 1
    if args.fail_on_warning and warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
