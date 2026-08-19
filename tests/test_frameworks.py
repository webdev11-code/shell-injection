#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test deteksi kerentanan framework spesifik (Struts2 / ThinkPHP / Shiro /
Fastjson) ala modul advanced xray."""

import json
import os
import re
import socket
import sys
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zqrya_exploit import core
from tests._server import FakeQ, FakeServer, parse_params, read_request, respond

MARKER = re.compile(r"X[A-Z0-9]{8}Y")


class TestStruts(unittest.TestCase):
    def test_s2045_content_type_ognl(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            ctype = headers.get("content-type", "")
            m = MARKER.search(ctype)
            if m and "%{" in ctype:
                respond(conn, 200, m.group(0).encode())
            else:
                respond(conn, 200, b"ok")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_struts(srv.url + "/index.action", core.make_session(), q)
            self.assertIn("struts-s2-045", q.finding_types())
        finally:
            srv.stop()

    def test_ognl_eval(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            if "233" in path:
                respond(conn, 200, b"54289")
            else:
                respond(conn, 200, b"ok")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_struts(srv.url + "/showcase/action.action", core.make_session(), q)
            self.assertIn("struts-ognl", q.finding_types())
        finally:
            srv.stop()


class TestThinkphp(unittest.TestCase):
    def test_invokefunction_rce(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            params = parse_params(method, path, headers, body)
            if "invokefunction" in (params.get("s", "") or "") or "invokefunction" in path:
                m = re.search(r"echo\s+(X[A-Z0-9]{8}Y)", params.get("vars[1][]", ""))
                if m:
                    respond(conn, 200, m.group(1).encode())
                    return
            respond(conn, 200, b"ok")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_thinkphp(srv.url + "/index.php", core.make_session(), q)
            self.assertIn("thinkphp-rce", q.finding_types())
        finally:
            srv.stop()

    def test_method_cve_2018_20062(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            params = parse_params(method, path, headers, body)
            if params.get("_method") == "__construct":
                m = re.search(r"echo\s+(X[A-Z0-9]{8}Y)", params.get("server[REQUEST_METHOD]", ""))
                if m:
                    respond(conn, 200, m.group(1).encode())
                    return
            respond(conn, 200, b"ok")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_thinkphp(srv.url + "/index.php", core.make_session(), q)
            self.assertIn("thinkphp-rce", q.finding_types())
        finally:
            srv.stop()


class TestShiro(unittest.TestCase):
    def test_rememberme_delete_me(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            cookie = headers.get("cookie", "")
            if "rememberMe" in cookie:
                respond(conn, 200, b"ok", {"Set-Cookie": "rememberMe=deleteMe; Path=/"})
            else:
                respond(conn, 200, b"ok")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_shiro(srv.url + "/", core.make_session(), q)
            self.assertIn("shiro", q.finding_types())
        finally:
            srv.stop()


class TestFastjson(unittest.TestCase):
    def test_local_http_callback(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        def handler(conn):
            method, path, headers, body = read_request(conn)
            try:
                obj = json.loads(body.decode("utf-8", "ignore"))
            except Exception:
                respond(conn, 200, b"{}")
                return

            def walk(o):
                if isinstance(o, dict):
                    if "val" in o:
                        yield o["val"]
                    for v in o.values():
                        yield from walk(v)
                elif isinstance(o, list):
                    for v in o:
                        yield from walk(v)

            for v in walk(obj):
                if isinstance(v, str) and v.startswith("http://"):
                    try:
                        urllib.request.urlopen(v, timeout=4)
                    except Exception:
                        pass
            respond(conn, 200, b"{}")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_fastjson(srv.url + "/api", core.make_session(), q,
                               host="127.0.0.1", port=port, wait=2)
            self.assertIn("fastjson", q.finding_types())
        finally:
            srv.stop()

    def test_domain_payload_sent(self):
        bodies = []

        def handler(conn):
            method, path, headers, body = read_request(conn)
            bodies.append(body.decode("utf-8", "ignore"))
            respond(conn, 200, b"{}")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_fastjson(srv.url + "/api", core.make_session(), q,
                               domain="x.interactsh.com")
            self.assertTrue(any("java.net.Inet4Address" in b for b in bodies))
            self.assertTrue(any("@type" in b for b in bodies))
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()
