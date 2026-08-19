#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test modul deteksi baru (ala xray): baseline, jsonp, upload, brute-force,
fingerprint, backup files, dan engine PoC kustom."""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zqrya_exploit import core
from tests._server import FakeQ, FakeServer, parse_params, read_request, respond


def spec(url, value="1", param="q"):
    return {"method": "GET", "url": url + "/vuln.php", "params": [(param, value)]}


class TestBaseline(unittest.TestCase):
    def test_missing_headers_finding(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            respond(conn, 200, b"ok", {"Server": "nginx"})

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_baseline(srv.url + "/", core.make_session(), q)
            self.assertIn("baseline", q.finding_types())
        finally:
            srv.stop()


class TestJsonp(unittest.TestCase):
    def test_callback_reflect_finding(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            params = parse_params(method, path, headers, body)
            cb = params.get("callback", "")
            respond(conn, 200, ("%s({\"ok\":1});" % cb).encode(),
                    {"Content-Type": "application/javascript"})

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_jsonp([spec(srv.url, "x", "callback")], core.make_session(), q)
            self.assertIn("jsonp", q.finding_types())
        finally:
            srv.stop()


class TestUpload(unittest.TestCase):
    def test_put_writeable_finding(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            if method == "PUT":
                respond(conn, 201, b"")
            elif core.UPLOAD_PROBE_NAME in path:
                respond(conn, 200, core.UPLOAD_PROBE_CONTENT.encode())
            else:
                respond(conn, 404, b"not found")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_upload(srv.url, core.make_session(), q, threads=5)
            self.assertIn("upload", q.finding_types())
        finally:
            srv.stop()

    def test_multipart_body_shape(self):
        body, ctype = core._multipart_body("file", "a.txt", "hello")
        self.assertIn("multipart/form-data", ctype)
        self.assertIn(b'name="file"; filename="a.txt"', body)
        self.assertIn(b"hello", body)


class TestBruteForce(unittest.TestCase):
    def test_basic_auth_weak_password(self):
        expected = base64.b64encode(b"admin:admin").decode()

        def handler(conn):
            method, path, headers, body = read_request(conn)
            auth = headers.get("authorization", "")
            if auth == "Basic " + expected:
                respond(conn, 200, b"welcome")
            else:
                respond(conn, 401, b"auth required", {"WWW-Authenticate": "Basic realm=x"})

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_brute_force(srv.url + "/", core.make_session(), q)
            self.assertIn("weak-password", q.finding_types())
        finally:
            srv.stop()


class TestFingerprint(unittest.TestCase):
    def test_fingerprint_finding(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            respond(conn, 200, b"<html>wp-content/themes/x</html>",
                    {"Server": "nginx/1.18.0"})

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_fingerprint(srv.url + "/", core.make_session(), q)
            self.assertIn("fingerprint", q.finding_types())
            detail = q.findings[0]["detail"]
            self.assertIn("nginx", detail)
        finally:
            srv.stop()


class TestBackupFiles(unittest.TestCase):
    def test_backup_file_finding(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            respond(conn, 200, b"<?php echo 1; ?>")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_backup_files(srv.url, core.make_session(), q, threads=5)
            self.assertIn("backup-file", q.finding_types())
        finally:
            srv.stop()


class TestPocEngine(unittest.TestCase):
    def test_eval_expression(self):
        resp = core._PoCResponse(200, "please login here", {"Server": "nginx"})
        self.assertTrue(core._eval_poc_expression(
            'response.status == 200 && response.body.contains("login")', resp))
        self.assertTrue(core._eval_poc_expression(
            'response.status == 200 || response.status == 500', resp))
        self.assertFalse(core._eval_poc_expression(
            'response.status != 200', resp))
        self.assertTrue(core._eval_poc_expression(
            'response.body.bcontains(b"login")', resp))
        self.assertTrue(core._eval_poc_expression(
            'response.headers.contains("nginx")', resp))

    def test_run_poc_matches(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            respond(conn, 200, b"login page")

        srv = FakeServer(handler)
        q = FakeQ()
        poc = {
            "name": "test-poc",
            "severity": "high",
            "rules": [{
                "method": "GET",
                "path": "/",
                "expression": 'response.status == 200 && response.body.contains("login")',
            }],
        }
        try:
            self.assertTrue(core.run_poc(poc, srv.url, core.make_session(), q))
            self.assertIn("poc-test-poc", q.finding_types())
        finally:
            srv.stop()


class TestPassiveScanSpec(unittest.TestCase):
    def test_passive_xss_finding(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            params = parse_params(method, path, headers, body)
            val = next(iter(params.values()), "")
            respond(conn, 200, ("<html>%s</html>" % val).encode())

        srv = FakeServer(handler)
        q = FakeQ()
        ctx = core._PassiveContext(core.make_session(), q)
        s = spec(srv.url, "1", "q")
        try:
            core._passive_scan_spec(ctx, s)
            self.assertIn("xss", q.finding_types())
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()
