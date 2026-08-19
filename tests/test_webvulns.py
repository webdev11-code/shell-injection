#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test scanner web lain: XSS, SSTI, LFI, open redirect, CORS/CRLF."""

import base64
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zqrya_exploit import core
from tests._server import FakeQ, FakeServer, parse_params, read_request, respond


def make_reflect_handler():
    """Reflect nilai parameter apa adanya (XSS reflected)."""
    def handler(conn):
        method, path, headers, body = read_request(conn)
        params = parse_params(method, path, headers, body)
        val = next(iter(params.values()), "")
        respond(conn, 200, ("<html>%s</html>" % val).encode())
    return handler


def make_ssti_handler():
    def handler(conn):
        method, path, headers, body = read_request(conn)
        params = parse_params(method, path, headers, body)
        val = next(iter(params.values()), "")
        if "7*7" in val:
            respond(conn, 200, b"Hasil: 49")
        else:
            respond(conn, 200, b"ok")
    return handler


def make_lfi_handler():
    def handler(conn):
        method, path, headers, body = read_request(conn)
        params = parse_params(method, path, headers, body)
        val = next(iter(params.values()), "")
        if "etc/passwd" in val:
            respond(conn, 200, b"root:x:0:0:root:/root:/bin/bash\n")
        elif "php://filter" in val:
            respond(conn, 200, base64.b64encode(b"<?php echo 1; ?>"))
        else:
            respond(conn, 200, b"ok")
    return handler


def make_redirect_handler():
    def handler(conn):
        method, path, headers, body = read_request(conn)
        params = parse_params(method, path, headers, body)
        val = next(iter(params.values()), "")
        if "evil.com" in val:
            respond(conn, 302, b"", {"Location": "https://evil.com/landing?x=1"})
        else:
            respond(conn, 200, b"ok")
    return handler


def make_headers_handler():
    def handler(conn):
        method, path, headers, body = read_request(conn)
        params = parse_params(method, path, headers, body)
        val = next(iter(params.values()), "")
        hdrs = {}
        if "evil.com" in headers.get("origin", ""):
            hdrs["Access-Control-Allow-Origin"] = "evil.com"
            hdrs["Access-Control-Allow-Credentials"] = "true"
        m = re.search(r"X-Injected: (X[A-Z0-9]{8}Y)", val)
        if m:
            hdrs["X-Injected"] = m.group(1)
        respond(conn, 200, b"ok", hdrs)
    return handler


def spec(url, value="1"):
    return {"method": "GET", "url": url + "/vuln.php", "params": [("q", value)]}


class TestXss(unittest.TestCase):
    def test_reflected_finding(self):
        srv = FakeServer(make_reflect_handler())
        q = FakeQ()
        try:
            core.scan_xss([spec(srv.url)], core.make_session(), q)
            self.assertIn("xss", q.finding_types())
        finally:
            srv.stop()


class TestSsti(unittest.TestCase):
    def test_finding(self):
        srv = FakeServer(make_ssti_handler())
        q = FakeQ()
        try:
            core.scan_ssti([spec(srv.url)], core.make_session(), q)
            self.assertIn("ssti", q.finding_types())
        finally:
            srv.stop()


class TestLfi(unittest.TestCase):
    def test_passwd_finding(self):
        srv = FakeServer(make_lfi_handler())
        q = FakeQ()
        try:
            core.scan_lfi([spec(srv.url)], core.make_session(), q)
            self.assertIn("lfi", q.finding_types())
            joined = "\n".join(q.lines)
            self.assertIn("root:", joined)
        finally:
            srv.stop()


class TestOpenRedirect(unittest.TestCase):
    def test_finding(self):
        srv = FakeServer(make_redirect_handler())
        q = FakeQ()
        try:
            core.scan_open_redirect([spec(srv.url)], core.make_session(), q)
            self.assertIn("open-redirect", q.finding_types())
        finally:
            srv.stop()


class TestHeaders(unittest.TestCase):
    def test_cors_finding(self):
        srv = FakeServer(make_headers_handler())
        q = FakeQ()
        try:
            core.scan_headers([spec(srv.url)], core.make_session(), q)
            self.assertIn("cors", q.finding_types())
        finally:
            srv.stop()

    def test_crlf_finding(self):
        srv = FakeServer(make_headers_handler())
        q = FakeQ()
        try:
            # nilai memuat CRLF + header injeksi
            spec_q = spec(srv.url, "1\r\nX-Injected: ")
            core.scan_headers([spec_q], core.make_session(), q)
            self.assertIn("crlf", q.finding_types())
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()