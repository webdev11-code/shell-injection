#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test passive proxy: capture, parsing HTTP mentah, dan HTTPS MITM (CA/leaf)."""

import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zqrya_exploit import core
from tests._server import FakeQ

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


class TestHttpSocket(unittest.TestCase):
    def test_read_http_request(self):
        a, b = socket.socketpair()
        try:
            a.sendall(b"GET /x?a=1 HTTP/1.1\r\nHost: example.com\r\n"
                      b"Content-Length: 4\r\n\r\nbody")
            method, path, headers, body = core._read_http_request_from_sock(b, timeout=5)
            self.assertEqual(method, "GET")
            self.assertEqual(path, "/x?a=1")
            self.assertEqual(headers.get("host"), "example.com")
            self.assertEqual(body, b"body")
        finally:
            a.close()
            b.close()

    def test_write_http_response(self):
        a, b = socket.socketpair()
        try:
            core._write_http_response(a, 200, [("Content-Type", "text/html")], b"hello")
            data = b.recv(65536)
            self.assertIn(b"HTTP/1.1 200 OK", data)
            self.assertIn(b"Content-Length: 5", data)
            self.assertTrue(data.endswith(b"hello"))
        finally:
            a.close()
            b.close()


class TestPassiveCapture(unittest.TestCase):
    def test_capture_builds_spec(self):
        q = FakeQ()
        ctx = core._PassiveContext(core.make_session(), q, auto_scan=False)
        core._passive_capture(ctx, "GET", "http://example.com/x?a=1", {}, b"")
        self.assertEqual(ctx.count, 1)
        self.assertEqual(len(ctx.specs), 1)
        self.assertEqual(ctx.specs[0]["params"], [("a", "1")])
        self.assertTrue(any("proxy #1" in line for line in q.lines))


class TestMitm(unittest.TestCase):
    def test_ca_fallback_without_crypto(self):
        if HAVE_CRYPTO:
            self.skipTest("cryptography terpasang; fallback tidak relevan")
        self.assertEqual(core._mitm_ca(), (None, None, None))

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography tidak terpasang")
    def test_ca_and_leaf_generation(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ca_cert, ca_key, cert_path = core._mitm_ca(certs_dir=d)
            self.assertIsNotNone(ca_cert)
            self.assertTrue(os.path.exists(cert_path))
            cert_pem, key_pem = core._mitm_leaf("example.com", ca_cert, ca_key)
            self.assertIn(b"BEGIN CERTIFICATE", cert_pem)
            ctx = core._mitm_ssl_context(cert_pem, key_pem)
            self.assertIsNotNone(ctx)


class TestMitmEndToEnd(unittest.TestCase):
    """Verifikasi penuh: klien (percaya CA) -> CONNECT -> TLS MITM -> upstream https."""

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography tidak terpasang")
    def test_https_decrypted_and_captured(self):
        import datetime
        import ipaddress
        import ssl
        import tempfile
        import threading
        import time

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        tmp = tempfile.mkdtemp()
        _ca_cert, _ca_key, ca_path = core._mitm_ca(certs_dir=tmp)

        # upstream: cert self-signed (klien TIDAK percaya) untuk 127.0.0.1
        up_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        up_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"127.0.0.1")])
        up_cert = (x509.CertificateBuilder()
                   .subject_name(up_name).issuer_name(up_name)
                   .public_key(up_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.datetime.now(datetime.timezone.utc)
                                     - datetime.timedelta(days=1))
                   .not_valid_after(datetime.datetime.now(datetime.timezone.utc)
                                    + datetime.timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName(
                       [x509.IPAddress(ipaddress.ip_address(u"127.0.0.1"))]), critical=False)
                   .sign(up_key, hashes.SHA256()))
        up_cert_file = os.path.join(tmp, "up.crt")
        up_key_file = os.path.join(tmp, "up.key")
        with open(up_cert_file, "wb") as f:
            f.write(up_cert.public_bytes(serialization.Encoding.PEM))
        with open(up_key_file, "wb") as f:
            f.write(up_key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.TraditionalOpenSSL,
                                         serialization.NoEncryption()))

        up_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        up_ctx.load_cert_chain(up_cert_file, up_key_file)

        def handle(conn):
            try:
                tls = up_ctx.wrap_socket(conn, server_side=True)
                req = core._read_http_request_from_sock(tls, timeout=10)
                if req:
                    core._write_http_response(tls, 200, [("Content-Type", "text/plain")],
                                              b"ok")
                tls.close()
            except Exception:
                pass

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(16)
        up_port = srv.getsockname()[1]

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    break
                threading.Thread(target=handle, args=(c,), daemon=True).start()

        threading.Thread(target=serve, daemon=True).start()

        q = FakeQ()
        ps = socket.socket()
        ps.bind(("127.0.0.1", 0))
        proxy_port = ps.getsockname()[1]
        ps.close()
        threading.Thread(target=core.run_passive,
                         args=("127.0.0.1", proxy_port, core.make_session(), q),
                         kwargs={"mitm": True, "certs_dir": tmp}, daemon=True).start()
        time.sleep(1.0)

        try:
            client_ctx = ssl.create_default_context(cafile=ca_path)
            raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
            raw.sendall(("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n"
                         % (up_port, up_port)).encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                resp += raw.recv(65536)
            tls = client_ctx.wrap_socket(raw, server_hostname="127.0.0.1")
            tls.sendall(b"GET /secret?a=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                        b"Connection: close\r\n\r\n")
            data = b""
            while True:
                try:
                    chunk = tls.recv(65536)
                except Exception:
                    break
                if not chunk:
                    break
                data += chunk
            tls.close()
            self.assertIn(b"ok", data)
        finally:
            srv.close()

        time.sleep(0.5)
        self.assertTrue(any("https://127.0.0.1/secret" in line for line in q.lines))


if __name__ == "__main__":
    unittest.main()
