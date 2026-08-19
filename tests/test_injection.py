#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test deteksi & eksploitasi command injection via server lokal."""

import os
import re
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zqrya_exploit import core
from tests._server import FakeQ, FakeServer, MARKER_RE, parse_params, read_request, respond


def make_cmdi_handler():
    """Reflect marker hasil `echo`; ekstrak output command antara S/E marker."""
    def handler(conn):
        method, path, headers, body = read_request(conn)
        params = parse_params(method, path, headers, body)
        val = next(iter(params.values()), "")
        m = re.search(r"echo (X[A-Z0-9]{8}Y); (.*?) 2>&1; echo (X[A-Z0-9]{8}Y)", val)
        if m:
            respond(conn, 200, (m.group(1) + m.group(2) + m.group(3)).encode())
            return
        if "echo" in val:
            respond(conn, 200, val.encode())
            return
        respond(conn, 200, b"ok")
    return handler


def make_sleep_handler(delay=1.2):
    """Sleep saat payload berisi `sleep`/`SLEEP` (time-based injection)."""
    def handler(conn):
        method, path, headers, body = read_request(conn)
        params = parse_params(method, path, headers, body)
        val = next(iter(params.values()), "").lower()
        if "sleep" in val:
            time.sleep(delay)
        respond(conn, 200, b"ok")
    return handler


class TestCommandInjection(unittest.TestCase):
    def setUp(self):
        self.srv = FakeServer(make_cmdi_handler())
        self.session = core.make_session()
        self.q = FakeQ()

    def tearDown(self):
        self.srv.stop()

    def spec(self):
        return {"method": "GET", "url": self.srv.url + "/vuln.php",
                "params": [("cmd", "1")]}

    def test_detect_and_finding(self):
        found = core.test_injection_spec(self.spec(), self.session, self.q)
        self.assertTrue(found)
        self.assertIn("command-injection", self.q.finding_types())

    def test_detect_param_injection_kind(self):
        kind = core.detect_param_injection(self.spec(), 0, self.session)
        self.assertIsNotNone(kind)
        self.assertIn("semicolon", kind)

    def test_execute_command_output(self):
        out = core.execute_command(self.spec(), 0, "id", self.session, self.q)
        self.assertEqual(out, "id")

    def test_find_vulnerable_params(self):
        vuln = core.find_vulnerable_params(self.srv.url + "/vuln.php?cmd=1",
                                           self.session, self.q)
        self.assertEqual(len(vuln), 1)
        spec, idx = vuln[0]
        self.assertEqual(spec["params"][idx][0], "cmd")

    def test_resolve_param_by_name(self):
        spec, idx = core.resolve_param_target(self.srv.url + "/vuln.php?cmd=1",
                                              self.session, self.q, param="cmd")
        self.assertIsNotNone(spec)
        self.assertEqual(spec["params"][idx][0], "cmd")

    def test_resolve_param_missing(self):
        spec, idx = core.resolve_param_target(self.srv.url + "/vuln.php?cmd=1",
                                              self.session, self.q, param="nope")
        self.assertIsNone(spec)
        self.assertIsNone(idx)

    def test_scan_command_injection(self):
        core.scan_command_injection([self.spec()], self.session, self.q)
        self.assertIn("command-injection", self.q.finding_types())


class TestTimeBased(unittest.TestCase):
    def setUp(self):
        self.srv = FakeServer(make_sleep_handler(1.2))
        self.session = core.make_session()

    def tearDown(self):
        self.srv.stop()

    def spec(self):
        return {"method": "GET", "url": self.srv.url + "/vuln.php",
                "params": [("cmd", "1")]}

    def test_time_based_test(self):
        elapsed = core.time_based_test(self.spec(), 0, "1", self.session, delay=1)
        self.assertIsNotNone(elapsed)
        self.assertGreaterEqual(elapsed, 1.0)

    def test_detect_param_injection_time_based(self):
        # detect_param_injection memakai delay default 5s -> server tidur 5.5s
        srv = FakeServer(make_sleep_handler(5.5))
        try:
            spec_ = {"method": "GET", "url": srv.url + "/vuln.php",
                     "params": [("cmd", "1")]}
            kind = core.detect_param_injection(spec_, 0, core.make_session())
        finally:
            srv.stop()
        self.assertIsNotNone(kind)
        self.assertIn("time-based", kind)


if __name__ == "__main__":
    unittest.main()