#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rebrand vendored dbstrike engine (a sqlmap fork) from "sqlmap" -> "zyra-sqli".

Skema:
  * identitas tampilan (banner, versi, user-agent, URL, copyright) -> "zyra-sqli"
  * identifier kode (class, env prefix, opsi, nama temp)      -> "zyra_sqli"
  * referensi modul/engine diarahkan ke module asli fork        -> "dbstrike"

Idempotent & aman terhadap file biner (UDF .so/.dll, shell payload).
Jalankan dari root project:
    python3 scripts/rebrand_dbstrike.py
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "zqrya_exploit", "tools", "dbstrike")

SKIP_DIRS = {".git", "__pycache__", "node_modules"}
BINARY_EXTS = {
    ".so", ".so_", ".dll", ".dll_", ".exe", ".bin", ".dat", ".png", ".jpg",
    ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pyc", ".pyo",
    ".7z", ".gz", ".zip", ".tar", ".xz", ".pdf",
}

# Placeholder untuk melindungi kata historis "mysqlmap" (bukan "sqlmap").
_PLACEHOLDER = "\x00MYSQLMAP\x00"

# Ordered replacements: literal string -> literal string.
# Urutan WAJIB dijaga: rule yang lebih spesifik (import sqlmapapi, nama file)
# harus diproses SEBELUM rule generik (sqlmapapi, import sqlmap, sqlmap).
REPLACEMENTS = [
    # --- proteksi kata yang kebetulan mengandung "sqlmap" ---
    ("mysqlmap", _PLACEHOLDER),

    # --- nama file (harus cocok dengan file yang sudah di-rename) ---
    ("sqlmapapi.yaml", "zyra-sqli-api.yaml"),
    ("sqlmapapi.py", "zyra-sqli-api.py"),

    # --- referensi modul / entry engine -> module fork (dbstrike) ---
    # WAJIB sebelum rule "sqlmapapi" generik & sebelum "import sqlmap"
    # (kalau tidak, "import sqlmapapi" jadi "import dbstrikeapi" atau
    # "import zyra_sqli_api").
    ("import sqlmapapi", "import dbstrike"),
    ("sqlmapapi", "zyra_sqli_api"),
    ("sqlmap.conf", "zyra-sqli.conf"),
    ("from sqlmap import", "from dbstrike import"),
    ("import sqlmap", "import dbstrike"),
    ("sqlmap.sqlmap", "dbstrike"),
    # Pola regex-escaped: pertahankan backslash di replacement agar
    # "\bsqlmap\.py\b" tetap jadi "\bdbstrike\.py\b" (bukan "\bdbstrike.py\b").
    (r"sqlmap\.py", r"dbstrike\.py"),
    ("sqlmap.py", "dbstrike.py"),

    # --- identifier compound ---
    ("sqlmapShell", "zyra_sqliShell"),
    ("--sqlmap-shell", "--zyra-sqli-shell"),
    ("sqlmapproject", "zqrya"),

    # --- case variants ---
    ("Sqlmap", "ZyraSqli"),
    ("SQLMap", "ZYRASqli"),
    ("SQLMAP", "ZYRA_SQLI"),

    # --- umum (comments/docs/data/temp prefix) ---
    ("sqlmap", "zyra_sqli"),

    # --- restore proteksi ---
    (_PLACEHOLDER, "mysqlmap"),

    # --- polish tampilan ke bentuk brand "zyra-sqli" (hanya teks non-identifier) ---
    ("zyra_sqli.org", "zyra-sqli.org"),
    ("zyra_sqli developers", "zyra-sqli developers"),
    ("zqrya/zyra_sqli", "zqrya/zyra-sqli"),
    ("zyra_sqli/%s#%s", "zyra-sqli/%s#%s"),
]


def is_binary(path):
    if os.path.splitext(path)[1].lower() in BINARY_EXTS:
        return True
    try:
        with open(path, "rb") as f:
            chunk = f.read(8192)
        if b"\x00" in chunk:
            return True
        chunk.decode("utf-8")
        return False
    except (UnicodeDecodeError, OSError):
        return True


def process_file(path):
    with open(path, "r", encoding="utf-8", newline="") as f:
        original = f.read()

    text = original
    for old, new in REPLACEMENTS:
        if old in text:
            text = text.replace(old, new)

    if text != original:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        return True
    return False


def main():
    changed = 0
    skipped = 0
    for dirpath, dirnames, filenames in os.walk(TARGET):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            if is_binary(path):
                skipped += 1
                continue
            if process_file(path):
                changed += 1
    print("files changed: %d" % changed)
    print("files skipped (binary): %d" % skipped)


if __name__ == "__main__":
    main()
