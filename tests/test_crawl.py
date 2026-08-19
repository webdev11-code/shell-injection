#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test FormParser (parse form HTML) dan crawl_forms (bangun request spec)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zqrya_exploit import core
from tests._server import FakeQ, FakeServer, read_request, respond


class TestFormParser(unittest.TestCase):
    def test_parses_forms_and_skips_submit(self):
        html = (
            '<form action="/search" method="get">'
            '<input name="q" value="a">'
            '<input type="submit" name="btn">'
            '<input type="file" name="f">'
            '<textarea name="note">x</textarea>'
            '<select name="opt"><option>1</option></select>'
            '</form>'
            '<form action="/login" method="POST">'
            '<input type="text" name="user">'
            '<input type="password" name="pass">'
            '</form>'
        )
        fp = core.FormParser()
        fp.feed(html)
        self.assertEqual(len(fp.forms), 2)
        f0 = fp.forms[0]
        self.assertEqual(f0["action"], "/search")
        self.assertEqual(f0["method"], "get")
        # catatan: FormParser hanya baca atribut value, bukan isi <textarea>
        self.assertEqual(f0["inputs"], [("q", "a"), ("note", ""), ("opt", "")])
        f1 = fp.forms[1]
        self.assertEqual(f1["method"], "post")
        self.assertEqual(f1["inputs"], [("user", ""), ("pass", "")])

    def test_form_without_inputs_ignored(self):
        fp = core.FormParser()
        fp.feed('<form action="/x"><input type="submit" name="s"></form>')
        self.assertEqual(fp.forms, [])


class TestCrawlForms(unittest.TestCase):
    HTML = (
        '<html><body>'
        '<form action="/search" method="get">'
        '<input name="q" value="">'
        '</form>'
        '<form action="/login" method="post">'
        '<input name="user"><input name="pass">'
        '</form>'
        '<a href="/list.php?page=2&sort=asc">list</a>'
        '<a href="#anchor">frag</a>'
        '<a href="https://evil.com/x?y=1">ext</a>'
        '</body></html>'
    )

    def test_builds_specs(self):
        def h(conn):
            read_request(conn)
            respond(conn, 200, self.HTML.encode())
        srv = FakeServer(h)
        base = srv.url
        try:
            specs = core.crawl_forms(base + "/index.php", core.make_session(), FakeQ())
        finally:
            srv.stop()

        keys = [(s["method"], s["url"], tuple(n for n, _ in s["params"]))
                for s in specs]
        self.assertIn(("GET", base + "/search", ("q",)), keys)
        self.assertIn(("POST", base + "/login", ("user", "pass")), keys)
        self.assertIn(("GET", base + "/list.php?page=2&sort=asc", ("page", "sort")), keys)
        self.assertIn(("GET", "https://evil.com/x?y=1", ("y",)), keys)
        # URL itu sendiri tanpa query -> tidak jadi spec
        self.assertNotIn(("GET", base + "/index.php", ()), keys)

    def test_url_with_query_becomes_spec(self):
        def h(conn):
            read_request(conn)
            respond(conn, 200, b"<html>no forms</html>")
        srv = FakeServer(h)
        try:
            specs = core.crawl_forms(srv.url + "/vuln.php?id=1", core.make_session(), FakeQ())
        finally:
            srv.stop()
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0]["method"], "GET")
        self.assertEqual(specs[0]["params"], [("id", "1")])

    def test_dedupe(self):
        def h(conn):
            read_request(conn)
            respond(conn, 200, b'<a href="/a.php?id=1&id=2">x</a>')
        srv = FakeServer(h)
        try:
            specs = core.crawl_forms(srv.url + "/", core.make_session(), FakeQ())
        finally:
            srv.stop()
        # id=1&id=2 -> satu spec dengan dua param
        self.assertEqual(len(specs), 1)


if __name__ == "__main__":
    unittest.main()