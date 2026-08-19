#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test deteksi critical CVE + exploit_cve_cmd (RCE command output retrieval)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zqrya_exploit import core
from tests._server import FakeQ, FakeServer, MARKER_RE, read_request, respond


def _echo_marker_handler(conn):
    method, path, headers, body = read_request(conn)
    txt = (path + " " + body.decode("latin-1", "ignore"))
    m = MARKER_RE.search(txt)
    respond(conn, 200, (m.group(0) if m else b"ok").encode("latin-1"))


class TestCveEchoRce(unittest.TestCase):
    def test_f5_ivanti_phpunit_fire(self):
        srv = FakeServer(_echo_marker_handler)
        q = FakeQ()
        try:
            core._cve_echo_scan(srv.url + "/", core.make_session(), q)
            types = q.finding_types()
            self.assertIn("f5-cve-2022-1388", types)
            self.assertIn("ivanti-cve-2024-21887", types)
            self.assertIn("phpunit-cve-2017-9841", types)
            # severity critical
            self.assertTrue(all(f["severity"] == "critical" for f in q.findings))
        finally:
            srv.stop()


class TestCveTraversal(unittest.TestCase):
    def test_traversal_reads_passwd(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            body = b"[global]\n" if "smb.conf" in path else b"root:x:0:0:root:/root:/bin/bash\n"
            respond(conn, 200, body)

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core._cve_traversal_scan(srv.url + "/", core.make_session(), q)
            types = q.finding_types()
            self.assertIn("citrix-cve-2019-19781", types)
            self.assertIn("apache-cve-2021-41773", types)
            self.assertIn("grafana-cve-2021-43798", types)
        finally:
            srv.stop()


class TestCveFingerprint(unittest.TestCase):
    def test_spring4shell_fingerprint(self):
        def handler(conn):
            read_request(conn)
            respond(conn, 200, b"<html>Whitelabel Error Page</html>")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core._cve_fingerprint_scan(srv.url + "/", core.make_session(), q)
            types = q.finding_types()
            self.assertIn("spring4shell-cve-2022-22965", types)
            self.assertEqual(q.findings[0]["severity"], "info")
        finally:
            srv.stop()


class TestCveSpecific(unittest.TestCase):
    def test_laravel_ignition(self):
        def handler(conn):
            read_request(conn)
            respond(conn, 200, b'{"can_execute_commands":true}')

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core._cve_laravel_ignition(srv.url + "/", core.make_session(), q)
            self.assertIn("laravel-cve-2021-3129", q.finding_types())
        finally:
            srv.stop()

    def test_papercut(self):
        def handler(conn):
            read_request(conn)
            respond(conn, 200, b"<title>PaperCut MF Setup Completed</title>")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core._cve_papercut(srv.url + "/", core.make_session(), q)
            self.assertIn("papercut-cve-2023-27350", q.finding_types())
        finally:
            srv.stop()


class TestExploitCveCmd(unittest.TestCase):
    def test_phpunit_command_output(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            txt = body.decode("latin-1", "ignore")
            markers = MARKER_RE.findall(txt)
            if len(markers) >= 2:
                respond(conn, 200, (markers[0] + "\nuid=0(root)\n" + markers[1]).encode("latin-1"))
            else:
                respond(conn, 200, b"")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            out = core.exploit_cve_cmd("phpunit-cve-2017-9841", srv.url + "/",
                                       "id", core.make_session(), q)
            self.assertIsNotNone(out)
            self.assertIn("uid=0(root)", out)
        finally:
            srv.stop()

    def test_unknown_cve(self):
        q = FakeQ()
        out = core.exploit_cve_cmd("nope", "http://127.0.0.1:1/", "id",
                                   core.make_session(), q)
        self.assertIsNone(out)


class TestAutoExploitCve(unittest.TestCase):
    def _echo_output_handler(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            txt = body.decode("latin-1", "ignore")
            markers = MARKER_RE.findall(txt)
            if len(markers) >= 2:
                respond(conn, 200, (markers[0] + "\nuid=0(root)\n" + markers[1]).encode("latin-1"))
            else:
                respond(conn, 200, b"")
        return handler

    def test_auto_exploit_fires_on_rce_finding(self):
        srv = FakeServer(self._echo_output_handler())
        q = FakeQ()
        q.finding("f5-cve-2022-1388", "detected", "critical")
        try:
            core.auto_exploit_cve(srv.url + "/", core.make_session(), q, command="id")
            self.assertIn("auto-exploited-cve", q.finding_types())
        finally:
            srv.stop()

    def test_no_exploit_without_rce_finding(self):
        q = FakeQ()
        q.finding("baseline", "missing header", "info")
        core.auto_exploit_cve("http://127.0.0.1:1/", core.make_session(), q, command="id")
        self.assertNotIn("auto-exploited-cve", q.finding_types())


if __name__ == "__main__":
    unittest.main()
