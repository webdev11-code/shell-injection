#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test helper HTTP (http_request / http_request_full / http_post_raw)
terhadap server lokal — jalur requests dan fallback urllib."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zqrya_exploit import core
from tests._server import FakeServer, read_request, respond


def echo_handler(conn):
    method, path, headers, body = read_request(conn)
    if method == "POST":
        respond(conn, 200, b"POST:" + body)
        return
    if path.startswith("/redir"):
        respond(conn, 302, b"", {"Location": "https://evil.com/landing?x=1"})
        return
    if path.startswith("/hdrs"):
        respond(conn, 200, b"hdrs-ok", {"X-Custom": "yes", "Content-Type": "text/plain"})
        return
    respond(conn, 200, b"hello world")


class TestHttpRequest(unittest.TestCase):
    def setUp(self):
        self.srv = FakeServer(echo_handler)
        self.session = core.make_session()

    def tearDown(self):
        self.srv.stop()

    def test_get(self):
        status, text = core.http_request("GET", self.srv.url + "/", None, self.session)
        self.assertEqual(status, 200)
        self.assertEqual(text, "hello world")

    def test_post_data_urlencoded(self):
        status, text = core.http_request("POST", self.srv.url + "/", {"a": "1", "b": "x y"},
                                         self.session)
        self.assertEqual(status, 200)
        self.assertTrue(text.startswith("POST:"))
        self.assertIn("a=1", text)
        self.assertIn("b=x+y", text)  # requests meng-encode spasi jadi +

    def test_get_without_requests(self):
        saved = core.requests
        core.requests = None
        try:
            status, text = core.http_request("GET", self.srv.url + "/", None, None)
            self.assertEqual((status, text), (200, "hello world"))
        finally:
            core.requests = saved

    def test_post_without_requests(self):
        saved = core.requests
        core.requests = None
        try:
            status, text = core.http_request("POST", self.srv.url + "/", {"a": "1"},
                                             None)
            self.assertTrue(text.startswith("POST:"))
            self.assertIn("a=1", text)
        finally:
            core.requests = saved

    def test_connection_error_raises_runtimeerror(self):
        # port yang tidak ada -> RuntimeError
        with self.assertRaises(RuntimeError):
            core.http_request("GET", "http://127.0.0.1:1/", None, self.session)


class TestHttpRequestFull(unittest.TestCase):
    def setUp(self):
        self.srv = FakeServer(echo_handler)
        self.session = core.make_session()

    def tearDown(self):
        self.srv.stop()

    def test_headers_and_location(self):
        status, headers, text, loc = core.http_request_full("GET", self.srv.url + "/hdrs",
                                                            None, self.session)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Custom"), "yes")
        self.assertEqual(text, "hdrs-ok")

    def test_redirect_not_followed(self):
        status, _h, _t, loc = core.http_request_full("GET", self.srv.url + "/redir",
                                                     None, self.session)
        self.assertEqual(status, 302)
        self.assertIn("evil.com", loc)

    def test_custom_headers(self):
        def h(conn):
            method, path, headers, body = read_request(conn)
            respond(conn, 200, headers.get("origin", "").encode())
        srv = FakeServer(h)
        try:
            _s, _h, text, _l = core.http_request_full("GET", srv.url + "/", None,
                                                      self.session,
                                                      headers={"Origin": "https://evil.com"})
            self.assertEqual(text, "https://evil.com")
        finally:
            srv.stop()

    def test_fallback_urllib(self):
        saved = core.requests
        core.requests = None
        try:
            status, headers, text, loc = core.http_request_full(
                "GET", self.srv.url + "/", None, None)
            self.assertEqual(status, 200)
            self.assertEqual(text, "hello world")
            self.assertEqual(headers, {})
            self.assertEqual(loc, "")
        finally:
            core.requests = saved


class TestHttpPostRaw(unittest.TestCase):
    def test_raw_body(self):
        def h(conn):
            method, path, headers, body = read_request(conn)
            respond(conn, 200, b"raw:" + body)
        srv = FakeServer(h)
        try:
            body = "<?xml version='1.0'?><r>xxe</r>"
            status, text = core.http_post_raw(srv.url + "/x", body,
                                              core.make_session(),
                                              content_type="application/xml")
            self.assertEqual(status, 200)
            self.assertEqual(text, "raw:" + body)
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()