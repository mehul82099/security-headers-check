#!/usr/bin/env python3
"""Tests for security-headers-check (stdlib unittest)."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import security_headers_check as shc

DATA = {
    "verified_at": "2026-11-01",
    "sources": [],
    "recommended": [],
    "info_leak": ["Server", "X-Powered-By", "X-AspNet-Version"],
    "deprecated": ["x-xss-protection", "public-key-pins", "expect-ct",
                   "feature-policy", "pragma"],
}

GOOD = {
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=()",
}


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = shc.main(argv)
    return code, out.getvalue(), err.getvalue()


def rules(findings):
    return {f.rule for f in findings}


def check(headers):
    return shc.check_headers(headers, "d.txt")


class ParseTests(unittest.TestCase):
    def test_simple_headers(self):
        h = shc.parse_dump("HTTP/2 200\ncontent-type: text/html\n\n")
        self.assertEqual(h.get("content-type"), "text/html")

    def test_names_lowered(self):
        h = shc.parse_dump("X-Content-Type-Options: nosniff\n")
        self.assertIn("x-content-type-options", h)

    def test_redirect_last_block_wins(self):
        dump = ("HTTP/1.1 301 Moved\nlocation: https://x/\n\n"
                "HTTP/2 200\nx-content-type-options: nosniff\n")
        h = shc.parse_dump(dump)
        self.assertIn("x-content-type-options", h)
        self.assertNotIn("location", h)

    def test_crlf_handled(self):
        h = shc.parse_dump("HTTP/2 200\r\nserver: nginx\r\n\r\n")
        self.assertEqual(h.get("server"), "nginx")

    def test_no_headers_empty(self):
        self.assertEqual(shc.parse_dump("just some text\n"), {})

    def test_first_occurrence_wins(self):
        h = shc.parse_dump("x-a: 1\nx-a: 2\n")
        self.assertEqual(h["x-a"], "1")

    def test_value_whitespace_trimmed(self):
        h = shc.parse_dump("x-a:    spaced   \n")
        self.assertEqual(h["x-a"], "spaced")


class MissingHeaderTests(unittest.TestCase):
    def test_empty_response_flags_core_set(self):
        rs = rules(check({}))
        self.assertIn("hsts-missing", rs)
        self.assertIn("csp-missing", rs)
        self.assertIn("x-content-type-options-missing", rs)
        self.assertIn("referrer-policy-missing", rs)
        self.assertIn("permissions-policy-missing", rs)
        self.assertIn("x-frame-options-missing", rs)

    def test_good_response_clean(self):
        self.assertEqual(check(dict(GOOD)), [])

    def test_xfo_missing_suppressed_by_frame_ancestors(self):
        h = dict(GOOD)
        self.assertNotIn("x-frame-options-missing", rules(check(h)))

    def test_xfo_missing_flagged_without_frame_ancestors(self):
        h = dict(GOOD)
        h["content-security-policy"] = "default-src 'self'"
        self.assertIn("x-frame-options-missing", rules(check(h)))

    def test_xfo_present_no_missing(self):
        h = dict(GOOD)
        h["content-security-policy"] = "default-src 'self'"
        h["x-frame-options"] = "deny"
        self.assertNotIn("x-frame-options-missing", rules(check(h)))


class HstsTests(unittest.TestCase):
    def base(self):
        return dict(GOOD)

    def test_no_max_age_is_error(self):
        h = self.base()
        h["strict-transport-security"] = "includeSubDomains"
        fs = check(h)
        self.assertIn("hsts-no-max-age", rules(fs))
        sev = {f.rule: f.severity for f in fs}
        self.assertEqual(sev["hsts-no-max-age"], "error")

    def test_max_age_zero_is_warning(self):
        h = self.base()
        h["strict-transport-security"] = "max-age=0"
        rs = rules(check(h))
        self.assertIn("hsts-max-age-zero", rs)
        self.assertNotIn("hsts-max-age-below-recommended", rs)

    def test_low_max_age_is_warning(self):
        h = self.base()
        h["strict-transport-security"] = "max-age=300; includeSubDomains"
        self.assertIn("hsts-max-age-below-recommended", rules(check(h)))

    def test_recommended_value_clean(self):
        h = self.base()
        rs = rules(check(h))
        self.assertNotIn("hsts-max-age-below-recommended", rs)
        self.assertNotIn("hsts-no-include-subdomains", rs)

    def test_missing_include_subdomains(self):
        h = self.base()
        h["strict-transport-security"] = "max-age=63072000"
        self.assertIn("hsts-no-include-subdomains", rules(check(h)))

    def test_quoted_max_age(self):
        h = self.base()
        h["strict-transport-security"] = 'max-age="63072000"; includeSubDomains'
        rs = rules(check(h))
        self.assertNotIn("hsts-max-age-below-recommended", rs)


class ValueTests(unittest.TestCase):
    def test_xcto_wrong_is_error(self):
        h = dict(GOOD)
        h["x-content-type-options"] = "sniff"
        fs = check(h)
        sev = {f.rule: f.severity for f in fs}
        self.assertEqual(sev["x-content-type-options-wrong"], "error")

    def test_xcto_case_insensitive(self):
        h = dict(GOOD)
        h["x-content-type-options"] = "NOSNIFF"
        self.assertNotIn("x-content-type-options-wrong",
                         rules(check(h)))

    def test_xfo_invalid_is_error(self):
        h = dict(GOOD)
        h["x-frame-options"] = "allow-from https://x"
        self.assertIn("x-frame-options-invalid", rules(check(h)))

    def test_xfo_sameorigin_ok(self):
        h = dict(GOOD)
        h["x-frame-options"] = "SAMEORIGIN"
        self.assertNotIn("x-frame-options-invalid", rules(check(h)))

    def test_csp_wildcard_default_src_error(self):
        h = dict(GOOD)
        h["content-security-policy"] = "default-src *"
        sev = {f.rule: f.severity for f in check(h)}
        self.assertEqual(sev.get("csp-wildcard"), "error")

    def test_csp_wildcard_script_src_error(self):
        h = dict(GOOD)
        h["content-security-policy"] = ("default-src 'self'; "
                                        "script-src *")
        self.assertIn("csp-wildcard", rules(check(h)))

    def test_csp_unsafe_inline_warning(self):
        h = dict(GOOD)
        h["content-security-policy"] = ("default-src 'self'; "
                                        "script-src 'self' 'unsafe-inline'")
        self.assertIn("csp-unsafe-inline", rules(check(h)))

    def test_csp_unsafe_eval_warning(self):
        h = dict(GOOD)
        h["content-security-policy"] = ("default-src 'self'; "
                                        "script-src 'unsafe-eval'")
        self.assertIn("csp-unsafe-eval", rules(check(h)))

    def test_csp_strict_clean(self):
        h = dict(GOOD)
        h["content-security-policy"] = ("default-src 'self'; "
                                        "object-src 'none'; "
                                        "frame-ancestors 'none'")
        self.assertEqual(check(h), [])


class ExposureTests(unittest.TestCase):
    def exposure(self, headers):
        return shc.check_exposure(headers, "d.txt", DATA)

    def test_server_flagged(self):
        fs = self.exposure({"server": "nginx"})
        self.assertEqual(fs[0].rule, "info-leak-header")
        self.assertEqual(fs[0].severity, "warning")

    def test_x_powered_by_flagged(self):
        self.assertIn("info-leak-header",
                      rules(self.exposure({"x-powered-by": "PHP/8.1"})))

    def test_deprecated_xss_protection(self):
        fs = self.exposure({"x-xss-protection": "1; mode=block"})
        self.assertEqual(fs[0].rule, "deprecated-header")

    def test_public_key_pins_deprecated(self):
        self.assertIn("deprecated-header",
                      rules(self.exposure({"public-key-pins": "x"})))

    def test_normal_header_clean(self):
        self.assertEqual(self.exposure({"content-type": "text/html"}), [])


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.data = os.path.join(self.dir, "headers.json")
        with open(self.data, "w", encoding="utf-8") as fh:
            json.dump(DATA, fh)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, content):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def good_dump(self):
        lines = ["HTTP/2 200"] + ["%s: %s" % kv for kv in GOOD.items()]
        return "\n".join(lines) + "\n"

    def test_good_dump_clean(self):
        p = self.write("good.txt", self.good_dump())
        code, out, _ = run(["--data", self.data, p])
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_empty_dump_missing_warnings_exit_zero(self):
        p = self.write("bare.txt", "HTTP/2 200\ncontent-type: text/html\n")
        code, out, _ = run(["--data", self.data, p])
        self.assertEqual(code, 0)
        self.assertIn("hsts-missing", out)

    def test_fail_on_warning(self):
        p = self.write("bare.txt", "HTTP/2 200\ncontent-type: text/html\n")
        code, _, _ = run(["--data", self.data, "--fail-on-warning", p])
        self.assertEqual(code, 1)

    def test_error_exit_one(self):
        p = self.write("bad.txt",
                       "HTTP/2 200\nx-content-type-options: sniff\n")
        code, out, _ = run(["--data", self.data, p])
        self.assertEqual(code, 1)
        self.assertIn("x-content-type-options-wrong", out)

    def test_ignore_suppresses(self):
        p = self.write("bare.txt", "HTTP/2 200\ncontent-type: text/html\n")
        code, out, _ = run(["--data", self.data, "--ignore",
                            "hsts-missing", "--ignore", "csp-missing",
                            "--ignore", "x-content-type-options-missing",
                            "--ignore", "referrer-policy-missing",
                            "--ignore", "permissions-policy-missing",
                            "--ignore", "x-frame-options-missing", p])
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_json_output(self):
        p = self.write("bad.txt",
                       "HTTP/2 200\nx-content-type-options: sniff\n")
        code, out, _ = run(["--data", self.data, "--format", "json", p])
        data = json.loads(out)
        self.assertEqual(data["summary"]["errors"], 1)
        self.assertEqual(data["findings"][0]["file"], p)

    def test_no_headers_exit_two(self):
        p = self.write("empty.txt", "hello world\n")
        code, _, err = run(["--data", self.data, p])
        self.assertEqual(code, 2)
        self.assertIn("no headers found", err)

    def test_missing_file_exit_two(self):
        code, _, err = run(["--data", self.data, "/nonexistent/x.txt"])
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)

    def test_bad_data_exit_two(self):
        p = self.write("x.txt", "HTTP/2 200\na: b\n")
        code, _, err = run(["--data", "/nonexistent/d.json", p])
        self.assertEqual(code, 2)
        self.assertIn("cannot load dataset", err)

    def test_multiple_files(self):
        p1 = self.write("a.txt", self.good_dump())
        p2 = self.write("b.txt", "HTTP/2 200\nserver: nginx\n")
        code, out, _ = run(["--data", self.data, p1, p2])
        self.assertEqual(code, 0)
        self.assertIn("info-leak-header", out)

    def test_counts_line(self):
        p = self.write("bad.txt",
                       "HTTP/2 200\nx-content-type-options: sniff\n"
                       "server: nginx\n")
        code, out, _ = run(["--data", self.data, p])
        self.assertIn("1 error(s)", out)


class DatasetTests(unittest.TestCase):
    """Structural checks on the shipped headers.json."""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "headers.json")
        with open(path, encoding="utf-8") as fh:
            cls.data = json.load(fh)

    def test_recommended_set_present(self):
        names = {h["name"].lower() for h in self.data["recommended"]}
        for expected in ("strict-transport-security",
                         "content-security-policy", "x-content-type-options",
                         "referrer-policy", "permissions-policy",
                         "x-frame-options"):
            self.assertIn(expected, names)

    def test_info_leak_core_entries(self):
        leak = {n.lower() for n in self.data["info_leak"]}
        for expected in ("server", "x-powered-by", "x-aspnet-version"):
            self.assertIn(expected, leak)

    def test_deprecated_entries(self):
        dep = set(self.data["deprecated"])
        self.assertIn("x-xss-protection", dep)
        self.assertIn("public-key-pins", dep)

    def test_sources_https(self):
        for s in self.data["sources"]:
            self.assertTrue(s["url"].startswith("https://"))

    def test_verified_at_iso(self):
        import datetime
        datetime.date.fromisoformat(self.data["verified_at"])


if __name__ == "__main__":
    unittest.main()
