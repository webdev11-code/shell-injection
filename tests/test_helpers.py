#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test fungsi-fungsi murni (tanpa jaringan) di core.py."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zqrya_exploit import core
from tests._server import FakeQ


class TestEncodeInjection(unittest.TestCase):
    def test_none(self):
        self.assertEqual(core.encode_injection("a b&c=d", "none"), "a b&c=d")
        self.assertEqual(core.encode_injection("a b", ""), "a b")

    def test_url(self):
        self.assertEqual(core.encode_injection("a b", "url"), "a%20b")

    def test_double_url(self):
        self.assertEqual(core.encode_injection("a b", "double-url"), "a%2520b")

    def test_hex(self):
        self.assertEqual(core.encode_injection("a b", "hex"), "%61%20%62")

    def test_double_hex(self):
        self.assertEqual(core.encode_injection("a b", "double-hex"), "%2561%2520%2562")

    def test_unknown_mode_passthrough(self):
        self.assertEqual(core.encode_injection("x", "bogus"), "x")

    def test_encoding_variants(self):
        self.assertEqual(core.encoding_variants("auto"), list(core.ENCODINGS))
        self.assertEqual(core.encoding_variants("url"), ["url"])
        self.assertEqual(core.encoding_variants("none"), ["none"])


class TestRender(unittest.TestCase):
    def test_all_placeholders(self):
        out = core.render("M=@@M@@ S=@@S@@ E=@@E@@ D=@@D@@ H=@@H@@ X=@@XC@@ B=@@B@@ C=@@C@@",
                          marker="M1", start="S1", end="E1", delay=3,
                          hexcmd="6869", xesc="\\x68", b64="aWQ=", cmd="id")
        self.assertEqual(out, "M=M1 S=S1 E=E1 D=3 H=6869 X=\\x68 B=aWQ= C=id")

    def test_cmd_last(self):
        # cmd diganti paling akhir: isi cmd tidak boleh kena placeholder lain
        out = core.render("@@C@@", cmd="@@M@@")
        self.assertEqual(out, "@@M@@")


class TestTamper(unittest.TestCase):
    def test_tamper_variants(self):
        self.assertEqual(core.tamper_variants("none"), ["none"])
        self.assertEqual(core.tamper_variants("hpp"), ["hpp"])
        self.assertEqual(core.tamper_variants("whitespace"), ["whitespace"])
        self.assertEqual(core.tamper_variants("ifsvars"), ["ifsvars"])
        self.assertEqual(core.tamper_variants("all"),
                         ["none", "whitespace", "ifsvars", "hpp"])

    def test_tamper_whitespace(self):
        self.assertEqual(core.tamper_injection("; echo X", "whitespace"),
                         ";\techo\tX")

    def test_tamper_ifsvars(self):
        self.assertEqual(core.tamper_injection("; echo X", "ifsvars"),
                         ";${IFS}echo${IFS}X")

    def test_tamper_unknown_passthrough(self):
        self.assertEqual(core.tamper_injection("; echo X", "bogus"), "; echo X")


class TestRandomMarker(unittest.TestCase):
    def test_format(self):
        for _ in range(20):
            m = core.random_marker()
            self.assertRegex(m, r"^X[A-Z0-9]{8}Y$")
            self.assertEqual(len(m), 10)


class TestGetQueryParams(unittest.TestCase):
    def test_parse(self):
        parsed, params = core.get_query_params("http://x.com/a.php?id=1&q=a%20b&empty=")
        self.assertEqual(parsed.netloc, "x.com")
        self.assertEqual(params, [("id", "1"), ("q", "a b"), ("empty", "")])


class TestBuildRequest(unittest.TestCase):
    def setUp(self):
        self.spec = {"method": "GET", "url": "http://x.com/a.php?id=1",
                     "params": [("id", "1"), ("q", "x")]}

    def test_get_puts_params_in_query(self):
        method, target, data = core.build_request(self.spec)
        self.assertEqual(method, "GET")
        self.assertIn("id=1", target)
        self.assertIn("q=x", target)
        self.assertIsNone(data)

    def test_replace_value(self):
        method, target, data = core.build_request(self.spec, 0, "2")
        self.assertIn("id=2", target)
        self.assertNotIn("id=1", target)

    def test_post_returns_data_dict(self):
        spec = {"method": "POST", "url": "http://x.com/login",
                "params": [("user", "a"), ("pass", "b")]}
        method, target, data = core.build_request(spec, 1, "c")
        self.assertEqual(method, "POST")
        self.assertEqual(target, "http://x.com/login")
        self.assertEqual(data, {"user": "a", "pass": "c"})


class TestSpecLabel(unittest.TestCase):
    def test_label(self):
        spec = {"method": "GET", "url": "http://x.com/a.php",
                "params": [("id", "1")]}
        self.assertEqual(core.spec_label(spec, 0), "[GET] http://x.com/a.php (param 'id')")
        self.assertIn("param '?'", core.spec_label(spec))


class TestDomainHelpers(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(core.registrable_domain("a.b.example.com"), "example.com")
        self.assertEqual(core.registrable_domain("example.com"), "example.com")
        self.assertEqual(core.registrable_domain("localhost"), "localhost")

    def test_in_scope(self):
        self.assertTrue(core.in_scope("sub.example.com", "example.com"))
        self.assertTrue(core.in_scope("example.com", "example.com"))
        self.assertFalse(core.in_scope("evil.com", "example.com"))
        self.assertFalse(core.in_scope("notexample.com", "example.com"))


class TestExtractLinks(unittest.TestCase):
    def test_extract(self):
        html = ('<a href="/x.php?id=1">a</a>'
                '<img src="https://cdn.e.com/i.png">'
                '<a href="#frag">f</a>'
                '<a href="javascript:void(0)">j</a>'
                '<form action="/submit"></form>')
        links = core.extract_links(html)
        self.assertIn("/x.php?id=1", links)
        self.assertIn("https://cdn.e.com/i.png", links)
        self.assertNotIn("#frag", links)
        self.assertNotIn("javascript:void(0)", links)
        # _LINK_RE mencakup atribut action (dipakai juga oleh crawl_forms)
        self.assertIn("/submit", links)


class TestDedupeSpecs(unittest.TestCase):
    def test_dedupe(self):
        specs = [
            {"method": "GET", "url": "http://x.com/a.php", "params": [("id", "1")]},
            {"method": "GET", "url": "http://x.com/a.php", "params": [("id", "2")]},
            {"method": "POST", "url": "http://x.com/a.php", "params": [("id", "1")]},
        ]
        out = core.dedupe_specs(specs)
        self.assertEqual(len(out), 2)


class TestLoadWordlist(unittest.TestCase):
    def test_load(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# komentar\n\nadmin\n/admin/\n  /api  \n")
            path = f.name
        try:
            entries = core.load_wordlist(path, FakeQ())
            self.assertEqual(entries, ["/admin", "/admin/", "/api"])
        finally:
            os.unlink(path)

    def test_missing_file_returns_empty(self):
        self.assertEqual(core.load_wordlist("/nonexistent/wl.txt", FakeQ()), [])

    def test_empty_path(self):
        self.assertEqual(core.load_wordlist("", FakeQ()), [])


class TestIsDirListing(unittest.TestCase):
    def test_markers(self):
        self.assertTrue(core.is_dir_listing("<title>Index of /admin</title>"))
        self.assertTrue(core.is_dir_listing("Parent Directory"))
        self.assertFalse(core.is_dir_listing("hello world"))
        self.assertFalse(core.is_dir_listing(""))


class TestRunConcurrent(unittest.TestCase):
    def test_parallel_results_and_none_filter(self):
        def worker(x):
            import time
            time.sleep(0.01)
            return x * 2 if x != 3 else None
        out = core.run_concurrent([1, 2, 3, 4], worker, threads=4)
        self.assertEqual(sorted(out), [2, 4, 8])

    def test_empty(self):
        self.assertEqual(core.run_concurrent([], lambda x: x), [])


if __name__ == "__main__":
    unittest.main()