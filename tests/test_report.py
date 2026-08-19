#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test Report (txt/json/html/save) dan ScanLogger."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zqrya_exploit import core


class TestReport(unittest.TestCase):
    def setUp(self):
        self.report = core.Report("http://target.test/")
        self.report.add_finding("sqli", "param 'id' -> error-based", "high")
        self.report.add_finding("xss", "param 'q' -> reflected", "medium")
        self.report.lines.append("[*] scan selesai")
        self.report.finish()

    def test_to_json_roundtrip(self):
        data = json.loads(self.report.to_json())
        self.assertEqual(data["tool"], "Zqrya-Exploit")
        self.assertEqual(data["target"], "http://target.test/")
        self.assertEqual(len(data["findings"]), 2)
        self.assertEqual(data["findings"][0]["type"], "sqli")
        self.assertEqual(data["findings"][0]["severity"], "high")
        self.assertIn("[*] scan selesai", data["log"])

    def test_to_txt_contains_log(self):
        self.assertIn("[*] scan selesai", self.report.to_txt())

    def test_to_html_contains_findings(self):
        html = self.report.to_html()
        self.assertIn("Zqrya-Exploit", html)
        self.assertIn("error-based", html)
        self.assertIn("reflected", html)

    def test_to_html_escapes(self):
        r = core.Report()
        r.add_finding("xss", "<script>alert(1)</script>")
        html = r.to_html()
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_empty_report(self):
        r = core.Report("http://x/")
        r.finish()
        data = json.loads(r.to_json())
        self.assertEqual(data["findings"], [])

    def test_save_extensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            for ext, loader in (("json", json.loads), ("txt", lambda s: s),
                                ("html", lambda s: s)):
                path = os.path.join(tmp, "report." + ext)
                saved = self.report.save(path)
                self.assertEqual(saved, path)
                content = open(path, encoding="utf-8").read()
                if ext == "json":
                    self.assertEqual(loader(content)["target"], "http://target.test/")
                elif ext == "html":
                    self.assertIn("<h1>", content)
                else:
                    self.assertIn("[*] scan selesai", content)

    def test_save_none_path(self):
        self.assertIsNone(self.report.save(None))


class TestScanLogger(unittest.TestCase):
    def test_put_forwards_to_report_and_sink(self):
        report = core.Report()
        sink = []
        q = core.ScanLogger(report=report, sink=sink.append)
        q.put("pesan")
        self.assertEqual(report.lines, ["pesan"])
        self.assertEqual(sink, ["pesan"])

    def test_finding_adds_to_report(self):
        report = core.Report()
        q = core.ScanLogger(report=report)
        q.finding("lfi", "etc/passwd terbaca", "high")
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0]["type"], "lfi")

    def test_no_report_or_sink_is_safe(self):
        q = core.ScanLogger()
        q.put("x")  # tidak boleh raise
        q.finding("t", "d")


if __name__ == "__main__":
    unittest.main()