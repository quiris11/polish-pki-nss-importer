#!/usr/bin/env bash
# import-nccert-pl-id.sh
# Downloads and imports all Polish PKI certificates into the user's
# NSS database (~/.pki/nssdb), making them trusted by GNOME Document
# Viewer (Evince/Papers), Okular, pdfsig, etc.
#
# Sources:
#   https://nccert.pl          — NCCert root CAs + all TSP certificates
#                                (parsed live from zaswiadczenia.htm)
#   http://repo.e-dowod.gov.pl — pl.ID (e-dowód / Polish ID card) PKI
#                                (parsed live from certyfikaty_pl.ID.txt)
#
# Usage:
#   chmod +x import-nccert-pl-id.sh
#   ./import-nccert-pl-id.sh
#
# Requirements: curl, openssl, certutil (nss-tools)

set -euo pipefail

# ── Flags ─────────────────────────────────────────────────────────────────────

ALL_CERTS=""
for arg in "$@"; do
    case "$arg" in
        --all) ALL_CERTS=1 ;;
        --help|-h)
            echo "Usage: $0 [--all]"
            echo ""
            echo "  (default)  Import only QES signing CA certificates (QCA)"
            echo "  --all      Import all certificates from nccert.pl"
            echo "             (includes TSA, OCSP, QTSA, QERDS, QVal, etc.)"
            exit 0
            ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

NSSDB=""  # populated by detect_nss_databases() below
TMPDIR=$(mktemp -d)
NCCERT_PAGE="https://nccert.pl/zaswiadczenia.htm"
NCCERT_BASE="https://nccert.pl/files"
EDOWOD_BASE="http://repo.e-dowod.gov.pl/certs"

# Colours
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ok()      { echo -e "${GREEN}  ✓ $*${NC}"; }
warn()    { echo -e "${YELLOW}  ! $*${NC}"; }
err()     { echo -e "${RED}  ✗ $*${NC}"; }
section() { echo -e "\n${CYAN}${BOLD}=== $* ===${NC}"; }

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

# ── Prerequisites ─────────────────────────────────────────────────────────────

echo "Checking prerequisites..."
for cmd in curl openssl certutil; do
    if ! command -v "$cmd" &>/dev/null; then
        err "Missing: $cmd"
        case "$cmd" in
            certutil) echo "  Install with: sudo dnf install nss-tools  # or: sudo apt install libnss3-tools" ;;
            *)        echo "  Install with: sudo dnf install $cmd" ;;
        esac
        exit 1
    fi
done
ok "All prerequisites present"

# ── NSS database detection ────────────────────────────────────────────────────
#
# Poppler (used by GNOME Document Viewer / Evince / Okular) searches NSS DBs
# in this priority order — first found wins, others are ignored:
#   1. Firefox profile  (~/.mozilla/firefox/*.default*/)
#   2. System-wide      (/etc/pki/nssdb)
#   3. User DB          (~/.pki/nssdb)
#
# This script detects which DBs exist and imports into ALL of them so that
# the correct one is populated regardless of which poppler picks up.

detect_nss_databases() {
    NSS_DBS=()

    # 1. Firefox profile DBs — checked in the same order poppler searches them:
    #
    #  a) ~/.mozilla/firefox/          — classic path (poppler always checks this)
    #  b) ~/.config/mozilla/firefox/   — XDG path used by Fedora; poppler checks
    #                                    this since 26.03 (your current 26.01 does
    #                                    NOT yet, but will after the next update)
    #  c) Flatpak Firefox              — sandboxed under ~/.var/app/
    #
    # We import into all found profiles so the script stays correct regardless
    # of which poppler version is running.
    for profile_dir in         "$HOME"/.mozilla/firefox/*.default*/         "$HOME"/.config/mozilla/firefox/*.default*/         "$HOME"/.var/app/org.mozilla.firefox/.mozilla/firefox/*.default*/; do
        [[ -f "${profile_dir}cert9.db" ]] && NSS_DBS+=("sql:${profile_dir}")
    done

    # 2. System-wide NSS DB
    if [[ -f "/etc/pki/nssdb/cert9.db" ]]; then
        NSS_DBS+=("sql:/etc/pki/nssdb")
    fi

    # 3. User NSS DB — create it if nothing else was found
    if [[ -f "$HOME/.pki/nssdb/cert9.db" ]]; then
        NSS_DBS+=("sql:$HOME/.pki/nssdb")
    elif [[ ${#NSS_DBS[@]} -eq 0 ]]; then
        echo "  No existing NSS database found — creating ~/.pki/nssdb ..."
        mkdir -p "$HOME/.pki/nssdb"
        certutil -d "sql:$HOME/.pki/nssdb" -N --empty-password
        NSS_DBS+=("sql:$HOME/.pki/nssdb")
        ok "Created ~/.pki/nssdb"
    fi
}

echo ""
echo "Detecting NSS databases..."
detect_nss_databases

if [[ ${#NSS_DBS[@]} -eq 0 ]]; then
    err "No NSS database found and could not create one. Aborting."
    exit 1
fi

for db in "${NSS_DBS[@]}"; do
    ok "Found: $db"
done

# Use the first (highest-priority) DB as the primary for duplicate checks
NSSDB="${NSS_DBS[0]}"

# ── Counters ──────────────────────────────────────────────────────────────────

COUNT_IMPORTED=0
COUNT_SKIPPED=0
COUNT_FAILED=0

# ── Helper: import a certificate from a URL ───────────────────────────────────
#
# import_from_url <url> <nickname> <trust_flags>
#   trust_flags: "CT,C,C" for root CAs, ",," for intermediates

import_from_url() {
    local url="$1"
    local nickname="$2"
    local trust="$3"

    local basename
    basename=$(basename "$url" | sed 's/%20/ /g')
    # Use a safe on-disk name (replace spaces with underscores)
    local safe_name
    safe_name=$(basename "$url" | sed 's/%20/_/g; s/ /_/g')
    local raw="$TMPDIR/$safe_name"
    local pem="$TMPDIR/${safe_name%.*}.pem"

    # Download (spaces in URL are already encoded by callers)
    if ! curl -sSf --max-time 20 -o "$raw" "$url" 2>/dev/null; then
        warn "Download failed: $basename — skipping"
        (( COUNT_FAILED++ )) || true
        return
    fi

    # Detect format: PEM starts with "-----", DER is binary
    if head -c 5 "$raw" | grep -q "^-----"; then
        cp "$raw" "$pem"
    else
        if ! openssl x509 -in "$raw" -inform DER -out "$pem" 2>/dev/null; then
            warn "Cannot parse: $basename — skipping"
            (( COUNT_FAILED++ )) || true
            return
        fi
    fi

    # Skip entirely if already present in the primary (highest-priority) DB
    if certutil -L -d "$NSSDB" 2>/dev/null | grep -qF "$nickname"; then
        ok "Already imported: $nickname"
        (( COUNT_SKIPPED++ )) || true
        return
    fi

    local any_imported=0
    local any_failed=0
    for db in "${NSS_DBS[@]}"; do
        # Skip if already in this specific DB
        if certutil -L -d "$db" 2>/dev/null | grep -qF "$nickname"; then
            continue
        fi
        if certutil -A -d "$db" -n "$nickname" -t "$trust" -a -i "$pem" 2>/dev/null; then
            any_imported=1
        else
            any_failed=1
        fi
    done

    if [[ $any_imported -eq 1 ]]; then
        ok "Imported: $nickname"
        (( COUNT_IMPORTED++ )) || true
    elif [[ $any_failed -eq 1 ]]; then
        warn "Import failed (possible duplicate key): $nickname"
        (( COUNT_FAILED++ )) || true
    fi
}

# ── Helper: build a nickname from a .crt/.cer filename ───────────────────────
#
# e.g. "PWPW_QCA_2017.crt"       → "PWPW QCA 2017"
#      "EuroCert QCA 2025.crt"   → "EuroCert QCA 2025"
#      "CENCERT QCA.cer"         → "CENCERT QCA"

nickname_from_filename() {
    local f="$1"
    # Strip extension, decode %20, replace underscores with spaces
    printf '%s' "$f" \
        | sed 's/\.[^.]*$//' \
        | sed 's/%20/ /g' \
        | sed 's/_/ /g'
}

# ── NCCert root CAs ───────────────────────────────────────────────────────────

section "Root CAs — NCCert / NBP"

import_from_url "$NCCERT_BASE/nccert2016.crt" "NCCert 2016 (NBP)" "CT,C,C"
import_from_url "$NCCERT_BASE/nccert.crt"     "NCCert 2009 (NBP)" "CT,C,C"

# ── NCCert TSP certificates — parsed live from zaswiadczenia.htm ──────────────

if [[ "$ALL_CERTS" == "1" ]]; then
    section "TSP certificates — parsed live from nccert.pl/zaswiadczenia.htm (all certs)"
else
    section "TSP certificates — parsed live from nccert.pl/zaswiadczenia.htm (QES QCA only)"
fi

NCCERT_HTML="$TMPDIR/zaswiadczenia.htm"

if curl -sSf --max-time 30 -o "$NCCERT_HTML" "$NCCERT_PAGE" 2>/dev/null; then
    ok "Fetched $NCCERT_PAGE"

    # Extract all .crt and .cer hrefs from the page.
    # The raw HTML uses relative hrefs like: href="files/EuroCert_QCA_2025.crt"
    # We match the filename portion after "files/" and prepend the base URL.
    mapfile -t CERT_URLS < <(
        # The page uses relative hrefs (files/Name.crt) so we match the
        # filename portion after "files/" — works for relative, absolute,
        # and URL-encoded variants alike.
        grep -oP '(?<=files/)[^)"<\s]+\.(?:crt|cer)' "$NCCERT_HTML" \
        | sort -u \
        | sed 's|^|https://nccert.pl/files/|'
    )

    if [[ ${#CERT_URLS[@]} -eq 0 ]]; then
        warn "No certificate links found on the page — layout may have changed"
    else
        echo "  Found ${#CERT_URLS[@]} certificate links"
        qes_count=0
        skipped_count=0
        for url in "${CERT_URLS[@]}"; do
            filename=$(basename "$url")

            # Root CAs are handled above; skip to avoid re-importing with wrong trust flags
            if [[ "$filename" == "nccert2016.crt" || "$filename" == "nccert.crt" ]]; then
                continue
            fi

            if [[ "$ALL_CERTS" != "1" ]]; then
                # QES default mode: import only Qualified CA certificates
                # (the ones that issue end-entity signing certificates).
                # Excluded: QTSA, TSA, OCSP, QERDS, QRDS, QDA, QDVCS,
                #           QODA, QRRA, QVal, QACSP — none of these are
                #           in the signing chain of a QES PDF signature.
                # Special case: Sigillum_2012.crt is a QCA despite the name.
                if [[ "$filename" != *"QCA"* &&                       "$filename" != *"qca"* &&                       "$filename" != "Sigillum_2012.crt" ]]; then
                    (( skipped_count++ )) || true
                    continue
                fi
            fi

            nickname=$(nickname_from_filename "$filename")
            import_from_url "$url" "$nickname" ",,"
            (( qes_count++ )) || true
        done
        echo "  Processed ${qes_count} QCA certificates${ALL_CERTS:+ (all-certs mode: skipped none)}, skipped ${skipped_count} non-signing CAs"
    fi
else
    warn "Could not fetch $NCCERT_PAGE"
    err "NCCert TSP certificates were NOT imported. Check your network."
fi

# ── pl.ID — e-dowód PKI (MSWiA / CPD) ────────────────────────────────────────
#
# Used for signatures made with the Polish national ID card (dowód osobisty)
# issued after February 2019. The root is self-signed (ECDSA P-384).
# Intermediate CAs are renewed annually; the list is maintained at:
#   http://repo.e-dowod.gov.pl/certs/certyfikaty_pl.ID.txt
#
# Three CA types exist per cohort:
#   Authentication — eIDAS LoA High (not a signing CA)
#   Authorization  — used for qualified electronic signatures (QES)
#   Presence       — physical presence confirmation

section "Root CA — pl.ID (e-dowód, MSWiA/CPD)"

import_from_url \
    "$EDOWOD_BASE/PLID_Root_CA.cer" \
    "pl.ID Root CA (MSWiA)" \
    "CT,C,C"

section "Intermediates — pl.ID (dynamic list from certyfikaty_pl.ID.txt)"

PLID_LIST_URL="$EDOWOD_BASE/certyfikaty_pl.ID.txt"
PLID_LIST="$TMPDIR/certyfikaty_pl.ID.txt"

if curl -sSf --max-time 15 -o "$PLID_LIST" "$PLID_LIST_URL" 2>/dev/null; then
    ok "Fetched $PLID_LIST_URL"

    while IFS= read -r cert_file || [[ -n "$cert_file" ]]; do
        [[ -z "${cert_file// }" ]] && continue

        # Build a human-readable nickname, e.g.:
        # PLID_Authorization_CA_20231125.cer → pl.ID Authorization CA 2023-11-25
        nickname=$(printf '%s' "$cert_file" \
            | sed 's/\.cer$//' \
            | sed 's/^PLID_/pl.ID /' \
            | sed 's/_CA_/ CA /' \
            | sed 's/_/ /g' \
            | sed -E 's/([0-9]{4})([0-9]{2})([0-9]{2})$/\1-\2-\3/')

        import_from_url "$EDOWOD_BASE/$cert_file" "$nickname" ",,"
    done < "$PLID_LIST"
else
    warn "Could not fetch $PLID_LIST_URL"
    warn "Note: repo.e-dowod.gov.pl uses plain HTTP — may be blocked by firewall/proxy."
    warn "Falling back to built-in static list (cohorts 2019–2025)..."

    for cohort in 20190221 20191207 20201202 20211204 20221126 20231125 20241116 20251122; do
        year="${cohort:0:4}"; mm="${cohort:4:2}"; dd="${cohort:6:2}"
        date_fmt="${year}-${mm}-${dd}"
        for role in Authentication Authorization Presence; do
            import_from_url \
                "$EDOWOD_BASE/PLID_${role}_CA_${cohort}.cer" \
                "pl.ID ${role} CA ${date_fmt}" \
                ",,"
        done
    done
fi

# ── Summary ───────────────────────────────────────────────────────────────────

section "Results"
echo -e "  Imported : ${GREEN}${COUNT_IMPORTED}${NC}"
echo -e "  Skipped  : ${YELLOW}${COUNT_SKIPPED}${NC} (already present)"
echo -e "  Failed   : ${RED}${COUNT_FAILED}${NC}"

for db in "${NSS_DBS[@]}"; do
    section "Certificates in: $db"
    certutil -L -d "$db"
done

echo ""
echo -e "${GREEN}${BOLD}Done!${NC} Restart GNOME Document Viewer and reopen your PDF."
echo "To verify a specific PDF run:  pdfsig your-document.pdf"
