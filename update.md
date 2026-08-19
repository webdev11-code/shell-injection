# Update — Checklist Lanjutan Project Zqrya-Exploit

> Dokumen status kerja + checklist supaya project bisa dilanjutkan kapan pun.
> Tanggal: 18 Agustus 2026.

## Ringkasan

Project **Zqrya-Exploit** adalah suite eksploitasi web (CLI + GUI) dengan 4 mesin
vendored: `dbstrike` (SQLi, fork sqlmap), `zq-radar`, `zq-fuzzer`, `zq-hunter`
(binari Go). Core engine ada di `zqrya_exploit/core.py` (±2750 baris).

Arah kerja yang sudah disepakati:

1. **Rebrand penuh** mesin `dbstrike` dari `sqlmap` → `zyra-sqli`.
2. **Binari Go dibiarkan** (tidak di-rebuild) karena source-nya tidak ada.
3. Rapikan project lalu **commit**.

## Status Saat Ini

### ✅ Sudah dikerjakan

- [x] Audit struktur project + konfirmasi arah kerja.
- [x] Analisis scope rebrand dbstrike:
  - 3213 kemunculan string `sqlmap` di ±678 file.
  - 3 file bernama `sqlmap*`, 28 nama class `Sqlmap*`, env prefix `SQLMAP_`,
    opsi `sqlmapShell`, flag `--sqlmap-shell`, token compound
    (`sqlmapproject`, `sqlmapapi`, `sqlmapoutput`, dst.).
- [x] **Rename 3 file** (sudah dieksekusi):
  - `sqlmap.conf`  → `zyra-sqli.conf`
  - `sqlmapapi.py` → `zyra-sqli-api.py`
  - `sqlmapapi.yaml` → `zyra-sqli-api.yaml`
- [x] Buat script rebrand di **`scripts/rebrand_dbstrike.py`** (BELUM dijalankan).

### ⏳ Belum dikerjakan

- [ ] Perbaiki script rebrand (ada bug ordering, lihat bawah).
- [ ] Jalankan script rebrand ke seluruh file teks dbstrike.
- [ ] Perbaiki referensi modul/engine stale (`import sqlmap` → `import dbstrike`, dst.).
- [ ] Verifikasi engine tetap jalan.
- [ ] Update integrasi level-atas (`core.py`, launcher `zq-dbstrike`) + README/docs.
- [ ] Bersihkan file sampah + commit.

## Checklist Lanjutan (langkah per langkah)

### 1. Perbaiki `scripts/rebrand_dbstrike.py`

Ada 3 bug ordering yang harus dibetulkan sebelum dijalankan:

1. **`import sqlmapapi` harus diproses SEBELUM** rule generic `sqlmapapi` →
   `zyra_sqli_api`. Saat ini urutannya terbalik, sehingga `import sqlmapapi`
   akan berubah jadi `import zyra_sqli_api` dulu (salah).
2. **`import sqlmapapi` harus diproses SEBELUM** `import sqlmap`, karena
   `text.replace("import sqlmap", ...)` ikut memotong prefix `import sqlmap`
   di dalam `import sqlmapapi` → jadi `import dbstrikeapi` (rusak).
3. Rule regex-escaped harus mempertahankan backslash:
   `(r"sqlmap\.py", r"dbstrike\.py")` — jangan pakai `"dbstrike.py"` polos,
   agar pola `\bsqlmap\.py\b` tetap jadi `\bdbstrike\.py\b`.

Urutan penggantian yang benar (literal replace, diurutkan):

```
mysqlmap → <PLACEHOLDER>            # lindungi kata historis "mysqlmap"
sqlmapapi.yaml → zyra-sqli-api.yaml
sqlmapapi.py   → zyra-sqli-api.py
import sqlmapapi → import dbstrike  # WAJIB sebelum sqlmapapi & import sqlmap
sqlmapapi      → zyra_sqli_api
sqlmap.conf    → zyra-sqli.conf
from sqlmap import → from dbstrike import
import sqlmap  → import dbstrike
sqlmap.sqlmap  → dbstrike
sqlmap\.py     → dbstrike\.py        # pola regex (raw string)
sqlmap.py      → dbstrike.py         # nama file literal
sqlmapShell    → zyra_sqliShell
--sqlmap-shell → --zyra-sqli-shell
sqlmapproject  → zqrya
Sqlmap         → ZyraSqli            # prefix class (SqlmapBaseException, ...)
SQLMap         → ZYRASqli
SQLMAP         → ZYRA_SQLI           # env prefix SQLMAP_ / SQLMAP_FILE / ...
sqlmap         → zyra_sqli           # umum: komentar, docs, prefix temp
<PLACEHOLDER>  → mysqlmap            # restore proteksi
# --- polish tampilan (brand pakai tanda hubung) ---
zyra_sqli.org        → zyra-sqli.org
zyra_sqli developers → zyra-sqli developers
zqrya/zyra_sqli      → zqrya/zyra-sqli
zyra_sqli/%s#%s      → zyra-sqli/%s#%s
```

Skema penamaan:
- **Identifier kode** (class, env, opsi, prefix temp) → `zyra_sqli` / `ZyraSqli` / `ZYRA_SQLI`.
- **Tampilan/brand** (banner, versi, user-agent, URL, copyright) → `zyra-sqli`.
- **Referensi modul/engine** → `dbstrike` (karena entry module fork memang `dbstrike.py`).

### 2. Jalankan script

```bash
cd <root project>
python3 scripts/rebrand_dbstrike.py
```

Script sudah skip file biner (UDF `.so_`/`.dll_`, payload shell) lewat deteksi
`\x00` + ekstensi, dan skip `.git`.

### 3. Perbaiki referensi stale (bila belum ter-cover script)

- `lib/utils/library.py` → `SQLMAP_FILE` harus menunjuk `dbstrike.py`
  (sebelumnya `sqlmap.py` — ini **bug** yang membuat `scan()` gagal cari engine).
- `sqlmapapi.py` (→ `zyra-sqli-api.py`) → `from sqlmap import modulePath`
  harus jadi `from dbstrike import modulePath`.
- `.github/workflows/tests.yml` → `import sqlmap; import sqlmapapi`
  jadi `import dbstrike`.

### 4. Verifikasi (harus semua hijau)

```bash
cd zqrya_exploit/tools/dbstrike
python3 dbstrike.py --version     # harus tampil 1.10.8.52#dev (atau versi baru)
python3 dbstrike.py -h | head     # help jalan
python3 -c "import sys; sys.path.insert(0,'.'); import dbstrike; print(dbstrike.scan)"  # facade library OK
python3 zyra-sqli-api.py -h       # REST API script jalan
```

Cek juga tidak ada sisa `sqlmap` yang tertinggal (kecuali kata historis `mysqlmap`):

```bash
cd zqrya_exploit/tools/dbstrike
grep -rIl 'sqlmap' . --exclude-dir=.git   # harus kosong / hanya mysqlmap
```

Opsional: jalankan sebagian test suite (`python3 -m pytest tests/test_library.py`).

### 5. Update integrasi level-atas + docs

- `zqrya_exploit/core.py` — komentar `"ala sqlmap dasar"` (baris ±1287) → ganti
  referensi ke `zyra-sqli`. Entri `EXTERNAL_TOOLS` tetap `dbstrike` (launcher
  `tools/bin/zq-dbstrike` tidak berubah).
- `zqrya_exploit/tools/bin/zq-dbstrike` — banner/komentar sudah "dbstrike engine",
  boleh disesuaikan jadi "zyra-sqli engine" bila mau.
- `README.md` — sesuaikan sebutan mesin `dbstrike` → `zyra-sqli` (opsional),
  dan catat file `update.md`.

### 6. Bersihkan + commit

- Hapus file sampah `aaa.txt` (isi "aaa", sisa percobaan).
- Pastikan `.gitignore` mengecualikan `payloads/*` dan `reports/*` (sudah).
- Stage semua file yang relevan lalu commit (pesan gaya repo: bahasa Indonesia,
  fokus "kenapa").

## Blocker / Catatan Penting

- **Binari Go** (`zq-radar` 144MB, `zq-hunter` 29MB, `zq-fuzzer` 9.8MB) adalah
  ELF stripped **tanpa source**. Tidak bisa di-rebuild. Keputusan: **dibiarkan**.
- **Script build di `/tmp` sudah hilang** — tidak ada source `.go` / `go.mod` /
  script rebrand mesin Go di filesystem. Kalau mau rebuild mesin Go, butuh
  source + script build baru (belum tersedia).
- dbstrike adalah **fork sqlmap v1.10.8.52#dev** (basis commit `cef41c7`),
  sudah di-rename `sqlmap.py` → `dbstrike.py` oleh fork sebelumnya.
- Nama brand `zyra-sqli` memakai tanda hubung; karena itu identifier kode wajib
  pakai `zyra_sqli` (Python/env tidak boleh tanda hubung).

## Ide Lanjutan (opsional, belum masuk scope)

- [ ] Tulis test suite untuk `core.py` (saat ini belum ada test).
- [ ] Rebrand ASCII-art banner dbstrike (logo sqlmap) jadi identitas baru.
- [ ] Tambah fitur/module vuln baru di `core.py`.
- [ ] Restore LICENSE dbstrike (fork ini menghapus `LICENSE` & `README.md` sqlmap).
