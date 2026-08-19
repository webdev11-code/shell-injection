#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test deteksi SQLi (error/boolean/time), ekstraksi UNION, blind extract,
dan dump database — via server lokal yang meniru aplikasi rentan."""

import os
import re
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zqrya_exploit import core
from tests._server import FakeQ, FakeServer, parse_params, read_request, respond

SECRETS = {"version()": "8.0.36", "user()": "root@localhost", "database()": "testdb"}

UNION_DATA = {
    "version()": "8.0.36",
    "user()": "root@localhost",
    "database()": "testdb",
    "select group_concat(schema_name) from information_schema.schemata":
        "information_schema,testdb",
    "select group_concat(table_name) from information_schema.tables where table_schema=database()":
        "users,orders",
}


def eval_cond(cond, secret_map):
    m = re.match(r"ASCII\(SUBSTRING\(\((.*?)\),(\d+),1\)\)>=(\d+)", cond)
    if m:
        expr, pos, n = m.group(1), int(m.group(2)), int(m.group(3))
        secret = secret_map.get(expr, "")
        return 0 < pos <= len(secret) and ord(secret[pos - 1]) >= n
    m = re.match(r"ASCII\(SUBSTRING\(\((.*?)\),(\d+),1\)\)>0", cond)
    if m:
        secret = secret_map.get(m.group(1), "")
        pos = int(m.group(2))
        return 0 < pos <= len(secret)
    return False


def make_error_sqli_handler():
    def handler(conn):
        method, path, headers, body = read_request(conn)
        params = parse_params(method, path, headers, body)
        val = next(iter(params.values()), "")
        if "extractvalue" in val or "updatexml" in val:
            respond(conn, 200, b"XPATH syntax error: '~8.0.36'")
            return
        if "'" in val:
            respond(conn, 200, b"SQL syntax error: You have an error in your SQL syntax")
            return
        respond(conn, 200, b"ok")
    return handler


def make_boolean_sqli_handler(secret_map):
    def handler(conn):
        method, path, headers, body = read_request(conn)
        params = parse_params(method, path, headers, body)
        val = next(iter(params.values()), "")
        if "1=1" in val:
            respond(conn, 200, b"T" * 200)
            return
        if "1=2" in val:
            respond(conn, 200, b"F" * 100)
            return
        m = re.search(r"AND \((.+?)\)-- -", val)
        if m and eval_cond(m.group(1), secret_map):
            respond(conn, 200, b"T" * 200)
            return
        respond(conn, 200, b"F" * 100)
    return handler


def make_union_sqli_handler(max_cols=3):
    def handler(conn):
        method, path, headers, body = read_request(conn)
        params = parse_params(method, path, headers, body)
        val = next(iter(params.values()), "")
        m = re.search(r"ORDER BY (\d+)", val)
        if m:
            n = int(m.group(1))
            if n > max_cols:
                respond(conn, 200, b"Unknown column '%d' in 'order clause'" % n)
            else:
                respond(conn, 200, b"ok")
            return
        m = re.search(r"concat\(0x([0-9a-f]+),\((.+?)\),0x([0-9a-f]+)\)", val)
        if m:
            start = bytes.fromhex(m.group(1)).decode()
            expr = m.group(2)
            end = bytes.fromhex(m.group(3)).decode()
            value = None
            tm = re.search(r"table_name=0x([0-9a-f]+)", expr)
            if tm and "column_name" in expr:
                table = bytes.fromhex(tm.group(1)).decode()
                value = {"users": "id,username,password"}.get(table)
            elif "from `" in expr:
                fm = re.search("from `(\\w+)`", expr)
                if fm:
                    value = {"users": "1,admin,secret"}.get(fm.group(1))
            else:
                value = UNION_DATA.get(expr)
            if value is not None:
                respond(conn, 200, (start + value + end).encode())
                return
        respond(conn, 200, b"ok")
    return handler


def make_time_sqli_handler(secret_map, delay=1.0):
    def handler(conn):
        method, path, headers, body = read_request(conn)
        params = parse_params(method, path, headers, body)
        val = next(iter(params.values()), "")
        m = re.search(r"AND IF\(\((.+?)\),SLEEP\((\d+)\),0\)-- -", val)
        if m:
            if eval_cond(m.group(1), secret_map):
                time.sleep(delay)
        elif "SLEEP(" in val:
            time.sleep(delay)
        respond(conn, 200, b"ok")
    return handler


def spec(url, value="1"):
    return {"method": "GET", "url": url + "/vuln.php", "params": [("id", value)]}


class TestDetectSqli(unittest.TestCase):
    def test_error_based(self):
        srv = FakeServer(make_error_sqli_handler())
        try:
            kind = core.detect_sqli(spec(srv.url), 0, "1", core.make_session())
            self.assertEqual(kind, "error-based (single-quote)")
        finally:
            srv.stop()

    def test_boolean_based(self):
        srv = FakeServer(make_boolean_sqli_handler(SECRETS))
        try:
            kind = core.detect_sqli(spec(srv.url), 0, "1", core.make_session())
            self.assertEqual(kind, "boolean-based")
        finally:
            srv.stop()

    def test_time_based(self):
        # detect_sqli memakai delay default 5s -> server tidur 5.5s
        srv = FakeServer(make_time_sqli_handler(SECRETS, 5.5))
        try:
            kind = core.detect_sqli(spec(srv.url), 0, "1", core.make_session())
            self.assertEqual(kind, "time-based")
        finally:
            srv.stop()

    def test_not_vulnerable(self):
        def h(conn):
            read_request(conn)
            respond(conn, 200, b"plain")
        srv = FakeServer(h)
        try:
            kind = core.detect_sqli(spec(srv.url), 0, "1", core.make_session())
            self.assertIsNone(kind)
        finally:
            srv.stop()


class TestSqliHelpers(unittest.TestCase):
    def test_boolean_test(self):
        srv = FakeServer(make_boolean_sqli_handler(SECRETS))
        try:
            self.assertTrue(core.sqli_boolean_test(spec(srv.url), 0, "1",
                                                   core.make_session()))
        finally:
            srv.stop()

    def test_time_test(self):
        srv = FakeServer(make_time_sqli_handler(SECRETS, 1.0))
        try:
            self.assertTrue(core.sqli_time_test(spec(srv.url), 0, "1",
                                                core.make_session(), delay=1))
        finally:
            srv.stop()

    def test_extract_version(self):
        srv = FakeServer(make_error_sqli_handler())
        try:
            ver = core.extract_sqli_version(spec(srv.url), 0, "1", core.make_session())
            # core mengembalikan isi pesan XPATH apa adanya (termasuk prefix '~')
            self.assertEqual(ver, "~8.0.36")
        finally:
            srv.stop()


class TestScanSqli(unittest.TestCase):
    def test_error_finding(self):
        srv = FakeServer(make_error_sqli_handler())
        q = FakeQ()
        try:
            hits = core.scan_sqli([spec(srv.url)], core.make_session(), q)
            self.assertEqual(len(hits), 1)
            self.assertIn("sqli", q.finding_types())
        finally:
            srv.stop()

    def test_boolean_finding(self):
        srv = FakeServer(make_boolean_sqli_handler(SECRETS))
        q = FakeQ()
        try:
            hits = core.scan_sqli([spec(srv.url)], core.make_session(), q)
            self.assertEqual(len(hits), 1)
        finally:
            srv.stop()


class TestUnionExtraction(unittest.TestCase):
    def setUp(self):
        self.srv = FakeServer(make_union_sqli_handler(3))
        self.session = core.make_session()

    def tearDown(self):
        self.srv.stop()

    def test_find_columns(self):
        n = core.sqli_find_columns(spec(self.srv.url), 0, "1", self.session)
        self.assertEqual(n, 3)

    def test_union_extract(self):
        val = core.sqli_union_extract(spec(self.srv.url), 0, "1", self.session,
                                      "version()")
        self.assertEqual(val, "8.0.36")

    def test_union_extract_unknown_expr_returns_none(self):
        val = core.sqli_union_extract(spec(self.srv.url), 0, "1", self.session,
                                      "select 12345")
        self.assertIsNone(val)

    def test_run_query(self):
        val = core.sqli_run_query(spec(self.srv.url), 0, "1", self.session,
                                  "version()")
        self.assertEqual(val, "8.0.36")


class TestDumpDatabase(unittest.TestCase):
    def test_full_chain(self):
        srv = FakeServer(make_union_sqli_handler(3))
        q = FakeQ()
        try:
            ok = core.sqli_dump_database(spec(srv.url), 0, "1",
                                         core.make_session(), q)
            self.assertTrue(ok)
            self.assertIn("sqli-dump", q.finding_types())
            joined = "\n".join(q.lines)
            self.assertIn("Jumlah kolom: 3", joined)
            self.assertIn("[version] 8.0.36", joined)
            self.assertIn("Databases: information_schema,testdb", joined)
            self.assertIn("Tables (database()): users,orders", joined)
            self.assertIn("Columns (users): id,username,password", joined)
            self.assertIn("Data (users", joined)
            self.assertIn("1,admin,secret", joined)
        finally:
            srv.stop()


class TestBlindExtraction(unittest.TestCase):
    def test_boolean_blind(self):
        srv = FakeServer(make_boolean_sqli_handler(SECRETS))
        try:
            val = core.sqli_blind_extract(spec(srv.url), 0, "1",
                                          core.make_session(), "version()")
            self.assertEqual(val, "8.0.36")
        finally:
            srv.stop()

    def test_time_blind(self):
        srv = FakeServer(make_time_sqli_handler(SECRETS, 1.0))
        try:
            val = core.sqli_blind_extract_time(spec(srv.url), 0, "1",
                                               core.make_session(), "version()",
                                               max_len=1, delay=1)
            self.assertEqual(val, "8")
        finally:
            srv.stop()


class TestResolveSqliParam(unittest.TestCase):
    def test_by_name(self):
        def h(conn):
            read_request(conn)
            respond(conn, 200, b"<html></html>")
        srv = FakeServer(h)
        try:
            s, i = core.resolve_sqli_param(srv.url + "/vuln.php?id=1&x=2",
                                           core.make_session(), FakeQ(), param="x")
            self.assertIsNotNone(s)
            self.assertEqual(s["params"][i], ("x", "2"))
        finally:
            srv.stop()

    def test_by_detection(self):
        srv = FakeServer(make_error_sqli_handler())
        try:
            s, i = core.resolve_sqli_param(srv.url + "/vuln.php?id=1",
                                           core.make_session(), FakeQ())
            self.assertIsNotNone(s)
            self.assertEqual(s["params"][i][0], "id")
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()