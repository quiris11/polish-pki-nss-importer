# polish-pki-nss-importer

Import Polish PKI certificates (NCCert QES + pl.ID e-dowód) into the NSS
database for PDF signature verification on Linux.

## Problem

On Linux, tools like **GNOME Document Viewer** (Evince / GNOME Papers),
**Okular**, and **pdfsig** use Mozilla's NSS library to verify PDF digital
signatures. NSS ships with no Polish CA certificates, so any PDF signed with:

- a **qualified electronic signature (QES)** from a Polish trust service
  provider (Certum/Asseco, Szafir/KIR, Sigillum/PWPW, EuroCert, Enigma/CenCert…)
- a **personal signature** from a Polish national ID card (**e-dowód**, issued
  after February 2019)

…will show as *"unknown issuer"* or *"certificate not trusted"* even when the
signature itself is cryptographically valid.

## Solution

This script downloads every CA certificate published by the two official Polish
PKI repositories and imports them into `~/.pki/nssdb`:

| Source | What it covers |
|---|---|
| [nccert.pl](https://nccert.pl) | NCCert root CAs (NBP) + all qualified TSP intermediate CAs |
| [repo.e-dowod.gov.pl](http://repo.e-dowod.gov.pl/certs/) | pl.ID root CA + annual intermediate CAs (e-dowód) |

After running the script, signatures from any of the providers below will
verify correctly — no Adobe Reader, no Windows required.

### Covered trust service providers (QES)

- **Certum / Asseco Data Systems** — CERTUM QCA (2011–2024)
- **Szafir / KIR** — SZAFIR QCA (2011–2021)
- **Sigillum / PWPW** — PWPW QCA / Sigillum (2012–2026)
- **EuroCert** — EuroCert QCA (2014–2025)
- **CenCert / Enigma SOI** — CenCert QCA / Enigma QCA (2009–2023)
- **Mobicert** — Mobicert QCA (2013)

### Covered personal signature PKI

- **pl.ID** (e-dowód) — Authorization CA cohorts 2019–2025

## Requirements

| Tool | Fedora/RHEL | Debian/Ubuntu |
|---|---|---|
| `curl` | `sudo dnf install curl` | `sudo apt install curl` |
| `openssl` | `sudo dnf install openssl` | `sudo apt install openssl` |
| `certutil` | `sudo dnf install nss-tools` | `sudo apt install libnss3-tools` |

## Usage

```bash
git clone https://github.com/youruser/polish-pki-nss-importer.git
cd polish-pki-nss-importer
chmod +x import-nccert.sh
./import-nccert.sh
```

Then **restart** GNOME Document Viewer (or Okular) and reopen the PDF.

The script is **idempotent** — safe to run multiple times. Already-imported
certificates are skipped automatically.

### Verify from the command line

```bash
pdfsig your-document.pdf
```

A correctly trusted signature shows:

```
- Signature Validation: Signature is Valid.
- Certificate Validation: Certificate is Trusted.
```

## How it works

1. Checks for `curl`, `openssl`, and `certutil`.
2. Creates `~/.pki/nssdb` (SQLite format) if it does not exist.
3. Downloads each certificate, auto-detects DER vs PEM, converts if needed.
4. Imports root CAs with trust flags `CT,C,C` (trusted CA for SSL, email,
   object signing); intermediate CAs with `,,` (chain only — they derive
   trust from the root).
5. For pl.ID, fetches `certyfikaty_pl.ID.txt` dynamically so new annual cohorts
   are picked up automatically. Falls back to a hardcoded list if the server
   is unreachable (it runs plain HTTP only).

### Which NSS database does poppler use?

Poppler (the PDF library behind Evince and Okular) searches in order:

1. Firefox profile NSS DB (`~/.mozilla/firefox/*.default/`)
2. System-wide `/etc/pki/nssdb`
3. User DB `~/.pki/nssdb`  ← **this script targets here**

Importing via Firefox's certificate manager (Settings → Privacy & Security →
View Certificates → Authorities → Import) also works and covers option 1.

## Troubleshooting

**`certutil: function failed: SEC_ERROR_BAD_DATABASE`**  
Your `~/.pki/nssdb` exists but was created without the `sql:` prefix. Run:
```bash
ls ~/.pki/nssdb/
```
If you see `cert9.db` and `key4.db` the DB is fine — the script handles this.
If you see `cert8.db` it is in the old DBM format; back it up and delete it,
then re-run the script.

**Signature still shows as unknown after running the script**  
Check which CA actually issued the certificate:
```bash
pdfsig your-document.pdf
```
Look at `Signer full Distinguished Name` → `Issuer`. If the issuer is not in
the list above, open an issue with the output and we will add it.

**pl.ID intermediates skipped (`Download failed`)**  
`repo.e-dowod.gov.pl` serves over plain HTTP and may be blocked by corporate
proxies or strict firewalls. The script will fall back to the built-in static
list covering cohorts 2019–2025.

## Sources

- [Narodowe Centrum Certyfikacji (NCCert)](https://nccert.pl/zaswiadczenia.htm)
- [Repozytorium e-dowód (MSWiA/CPD)](http://repo.e-dowod.gov.pl/certs/)
- [burghardt/plid-pdf-verifier](https://github.com/burghardt/plid-pdf-verifier) — inspiration for the pl.ID section
