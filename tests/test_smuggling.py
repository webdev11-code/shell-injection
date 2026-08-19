#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test scan_smuggling: server normal (tanpa false positive) dan server
desync palsu (CL.TE / TE.CL harus terdeteksi)."""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zqrya_exploit import core
from tests._server import FakeQ, FakeServer, read_request, respond


def make_desync_handler(cl_timeout):
    """Server yang menggantung (tanpa respons) saat Content-Length == cl_timeout."""
    def handler(conn):
        try:
            _m, _p, headers, _b = read_request(conn)
            cl = int(headers.get("content-length", 0) or 0)
            if cl == cl_timeout:
                time.sleep(30)  # simulasikan back-end yang menunggu framing
                return
            respond(conn, 200, b"OK")
        except Exception:
            pass
    return handler


class TestSmuggling(unittest.TestCase):
    def test_normal_server_no_finding(self):
        def h(conn):
            read_request(conn)
            respond(conn, 200, b"OK")
        srv = FakeServer(h)
        q = FakeQ()
        try:
            core.scan_smuggling(srv.url + "/", None, q, timeout=1.5, retries=1)
            self.assertEqual(q.finding_types(), [])
        finally:
            srv.stop()

    def test_clte_desync_detected(self):
        srv = FakeServer(make_desync_handler(4))
        q = FakeQ()
        try:
            core.scan_smuggling(srv.url + "/", None, q, timeout=1.5, retries=1)
            types = q.finding_types()
            self.assertIn("smuggling", types)
            details = " ".join(f["detail"] for f in q.findings)
            self.assertIn("CL.TE", details)
        finally:
            srv.stop()

    def test_tecl_desync_detected(self):
        srv = FakeServer(make_desync_handler(6))
        q = FakeQ()
        try:
            core.scan_smuggling(srv.url + "/", None, q, timeout=1.5, retries=1)
            details = " ".join(f["detail"] for f in q.findings)
            self.assertIn("TE.CL", details)
        finally:
            srv.stop()

    def test_unreachable_reports_failure(self):
        q = FakeQ()
        core.scan_smuggling("http://127.0.0.1:1/", None, q, timeout=1.0, retries=1)
        joined = "\n".join(q.lines)
        self.assertIn("Gagal terhubung", joined)


if __name__ == "__main__":
    unittest.main()