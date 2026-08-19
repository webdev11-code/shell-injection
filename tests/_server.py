#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Helper bersama untuk test suite core.py: server HTTP lokal (threaded),
parser request mentah, helper respons, dan logger tiruan (FakeQ).
Semua test berjalan offline di 127.0.0.1 dengan port ephemeral.
"""

import re
import socket
import threading
import urllib.parse

MARKER_RE = re.compile(r"X[A-Z0-9]{8}Y")


class FakeServer:
    """Server HTTP lokal satu-koneksi-per-thread dengan handler kustom."""

    def __init__(self, handler):
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(32)
        self._handler = handler
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()

    @property
    def port(self):
        return self._srv.getsockname()[1]

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.port

    def _loop(self):
        while self._running:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            self._handler(conn)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def stop(self):
        self._running = False
        try:
            self._srv.close()
        except Exception:
            pass


def read_request(conn, timeout=15):
    """Baca satu request HTTP mentah; return (method, path, headers, body)."""
    data = b""
    conn.settimeout(timeout)
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    request_line = lines[0].decode("latin-1")
    parts = request_line.split(" ")
    method = parts[0].upper()
    path = parts[1] if len(parts) > 1 else "/"
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.strip().decode("latin-1").lower()] = v.strip().decode("latin-1")
    cl = int(headers.get("content-length", 0) or 0)
    while len(body) < cl:
        chunk = conn.recv(65536)
        if not chunk:
            break
        body += chunk
    return method, path, headers, body


def parse_params(method, path, headers, body):
    """Decode parameter GET (query) dan/atau POST (form-urlencoded)."""
    params = {}
    parsed = urllib.parse.urlparse(path)
    params.update(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    ctype = headers.get("content-type", "")
    if method == "POST" and body and "form-urlencoded" in ctype:
        params.update(urllib.parse.parse_qsl(body.decode("latin-1"),
                                             keep_blank_values=True))
    return params


def respond(conn, status=200, body=b"", headers=None, close=True):
    """Kirim respons HTTP sederhana."""
    reasons = {200: "OK", 204: "No Content", 302: "Found", 400: "Bad Request",
               403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
               500: "Internal Server Error"}
    hdrs = dict(headers or {})
    hdrs.setdefault("Content-Length", str(len(body)))
    out = "HTTP/1.1 %d %s\r\n" % (status, reasons.get(status, "OK"))
    for k, v in hdrs.items():
        out += "%s: %s\r\n" % (k, v)
    out += "Connection: %s\r\n\r\n" % ("close" if close else "keep-alive")
    conn.sendall(out.encode("latin-1") + body)


class FakeQ:
    """Tiruan ScanLogger: kumpulkan log + finding untuk asersi test."""

    def __init__(self):
        self.lines = []
        self.findings = []

    def put(self, msg):
        self.lines.append(msg)

    def finding(self, ftype, detail, severity="high"):
        self.findings.append({"type": ftype, "detail": detail, "severity": severity})

    def finding_types(self):
        return [f["type"] for f in self.findings]