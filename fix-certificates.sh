#!/usr/bin/env bash
# =============================================================================
# fix-certificates.sh
#
# Assess and remediate the eMudhra intermediate CA compromise (October 2026)
# on a macOS host and in every conda environment on that host.
#
# Background:
#   The private keys of eight eMudhra intermediate CA certificates were
#   trivially recoverable (single/double digit entropy). They chain to two
#   trust anchors:
#     * AAA Certificate Services        (Comodo / Sectigo)
#     * emSign ECC Root CA - G3         (eMudhra)
#   Clients that still trust those anchors can be impersonated.
#   See: https://emudhra.we-have-a-problem.com/
#
#   Apple has blocked the intermediates in the macOS *keychain*, but the
#   command line tools (/usr/bin/curl, git, perl, ruby, openssl) and the
#   built-in python3 verify against /etc/ssl/cert.pem, which is NOT updated.
#   On top of that every conda environment ships its own certifi bundle and
#   its own OpenSSL CA bundle (ssl/cacert.pem).
#
# Usage:
#   ./fix-certificates.sh                 # same as: assess
#   ./fix-certificates.sh assess          # read-only assessment (default)
#   ./fix-certificates.sh apply           # apply the fixes
#   ./fix-certificates.sh backup          # snapshot every trust store, change nothing
#   ./fix-certificates.sh restore         # put the newest snapshot back
#
# Options:
#   -n, --dry-run        apply: only show what would be changed
#   -y, --yes            assume "yes", never prompt (also accepts the backup offer)
#       --offline        do not contact the checker hosts (no network probes)
#       --json           assess: also print a machine readable summary
#       --no-conda       skip the conda environment sweep
#       --no-pip         skip the pip / python remediation
#       --no-system      skip the /etc/ssl/cert.pem remediation
#       --no-backup      apply: do not offer the full trust store snapshot
#       --timeout N      network timeout in seconds (default 15)
#   -h, --help           show this help
#
# Exit codes:
#   0  nothing left to fix
#   1  something is still affected (assess) / remediation incomplete (apply)
#   2  usage or environment error
# =============================================================================

set -uo pipefail

VERSION="2.0"

# -----------------------------------------------------------------------------
# Compromised trust anchors (SHA-256 over the DER of the root certificate).
# Source: https://emudhra.we-have-a-problem.com/roots.json
# -----------------------------------------------------------------------------
FP_AAA="D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4"
FP_EMSIGN_G3="86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B"
BAD_ROOT_FPS="$FP_AAA $FP_EMSIGN_G3"

# Compromised intermediate CAs (SHA-256 of SubjectPublicKeyInfo), informational.
BAD_INTERMEDIATE_SPKIS="EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105 \
43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B \
E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41 \
49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F \
63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8 \
5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0 \
EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6 \
92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30"

# Hosts that serve certificates chaining to the compromised intermediates.
PROBE_URLS="
https://dv-g3b-emudhra.we-have-a-problem.com/
https://dv-g3b-aaa-emudhra.we-have-a-problem.com/
https://dv-g3b-noct-emudhra.we-have-a-problem.com/
https://dv-g3b-aaa-noct-emudhra.we-have-a-problem.com/
"

# -----------------------------------------------------------------------------
# Defaults / CLI
# -----------------------------------------------------------------------------
ACTION="assess"
DRY_RUN=0
ASSUME_YES=0
OFFLINE=0
JSON_OUT=0
DO_CONDA=1
DO_PIP=1
DO_SYSTEM=1
DO_BACKUP=1
TIMEOUT=15

SELF="$(basename "$0")"

print_help() {
    awk 'NR==1{next} /^# ={10,}/{n++; if(n==2) exit; next} {sub(/^# ?/,""); print}' "$0"
}

while [ $# -gt 0 ]; do
    case "$1" in
        assess|check|status) ACTION="assess" ;;
        apply|fix|remediate) ACTION="apply" ;;
        restore|revert|undo) ACTION="restore" ;;
        backup|snapshot) ACTION="backup" ;;
        -n|--dry-run)   DRY_RUN=1 ;;
        -y|--yes)       ASSUME_YES=1 ;;
        --offline)      OFFLINE=1 ;;
        --json)         JSON_OUT=1 ;;
        --no-conda)     DO_CONDA=0 ;;
        --no-pip)       DO_PIP=0 ;;
        --no-system)    DO_SYSTEM=0 ;;
        --backup)       DO_BACKUP=1 ;;
        --no-backup)    DO_BACKUP=0 ;;
        --timeout)      shift; TIMEOUT="${1:-15}" ;;
        -h|--help)      print_help; exit 0 ;;
        *) printf 'Unknown argument: %s\n\n' "$1" >&2; print_help >&2; exit 2 ;;
    esac
    shift
done

# When --json is given, everything human readable goes to stderr and stdout
# carries nothing but the JSON document, so it can be piped straight into jq.
if [ "$JSON_OUT" -eq 1 ]; then
    exec 3>&1
    exec 1>&2
fi

# -----------------------------------------------------------------------------
# Terminal helpers
# -----------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi

# Unicode punctuation, needed because bash does not expand escapes inside %s
# arguments - only inside the printf format string itself.
DASH=$'\342\200\224'    # em dash
BULLET=$'\342\200\242'  # bullet

hdr()  { printf '\n%s%s%s\n' "$C_BOLD$C_BLUE" "$1" "$C_RESET"; }
sub()  { printf '\n%s%s%s\n' "$C_BOLD" "$1" "$C_RESET"; }
info() { printf '  %s\n' "$1"; }
ok()   { printf '  %s[ ok ]%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
bad()  { printf '  %s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$1"; }
warn() { printf '  %s[warn]%s %s\n' "$C_YELLOW" "$C_RESET" "$1"; }
note() { printf '  %s%s%s\n' "$C_DIM" "$1" "$C_RESET"; }

# -----------------------------------------------------------------------------
# Progress reporting
#
# begin_check prints "... checking <label>" and end_check replaces that same
# line with the result, so the user always sees which trust store is currently
# being investigated without the report growing by one line per check.
# -----------------------------------------------------------------------------
CHECK_ACTIVE=0
CHECK_LABEL=""

begin_check() {  # $1 indent, $2 label
    CHECK_ACTIVE=0
    CHECK_LABEL="$2"
    if [ -t 1 ]; then
        printf '%*s%s\342\200\246 checking %s%s' "$1" "" "$C_DIM" "$2" "$C_RESET"
        CHECK_ACTIVE=1
    fi
}

end_check() {  # $1 color, $2 tag, $3 text, $4 indent
    local color="$1" tag="$2" text="$3" indent="${4:-2}"
    [ "$CHECK_ACTIVE" -eq 1 ] && printf '\r\033[K'
    printf '%*s%s[%s]%s %s\n' "$indent" "" "$color" "$tag" "$C_RESET" "$text"
    CHECK_ACTIVE=0
}

# -----------------------------------------------------------------------------
# Result collection:  STATUS \t SECTION \t TARGET \t DETAIL
# -----------------------------------------------------------------------------
RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/fix-ca-results.XXXXXX")" || exit 2
REMEDIATION_FILE=""
cleanup() { rm -f "$RESULTS_FILE" ${REMEDIATION_FILE:+"$REMEDIATION_FILE"} 2>/dev/null; }
trap cleanup EXIT

record() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RESULTS_FILE"; }

count_status() { count_status_in "$RESULTS_FILE" "$1"; }

count_status_in() {
    [ -f "$1" ] || { echo 0; return; }
    awk -F'\t' -v s="$2" '$1==s{n++} END{print n+0}' "$1"
}

# -----------------------------------------------------------------------------
# Tool discovery
# -----------------------------------------------------------------------------
OPENSSL=""
for cand in /usr/bin/openssl /opt/homebrew/bin/openssl /usr/local/bin/openssl; do
    [ -x "$cand" ] && OPENSSL="$cand" && break
done
[ -n "$OPENSSL" ] || OPENSSL="$(command -v openssl 2>/dev/null || true)"

PYTHON=""
for cand in /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    [ -x "$cand" ] && PYTHON="$cand" && break
done
[ -n "$PYTHON" ] || PYTHON="$(command -v python3 2>/dev/null || true)"

CURL=""
for cand in /usr/bin/curl /opt/homebrew/bin/curl /usr/local/bin/curl; do
    [ -x "$cand" ] && CURL="$cand" && break
done
[ -n "$CURL" ] || CURL="$(command -v curl 2>/dev/null || true)"

# -----------------------------------------------------------------------------
# Bundle inspection
#
# fingerprints_of_bundle <file>...
#   Prints "<sha256-upper>\t<path>" for every certificate in every file.
#   Uses python (hashlib) when available because it is ~50x faster than
#   shelling out to openssl once per certificate; falls back to openssl.
# -----------------------------------------------------------------------------
fingerprints_of_bundle() {
    if [ -n "$PYTHON" ]; then
        "$PYTHON" - "$@" <<'PYEOF'
import base64, hashlib, re, sys
pat = re.compile(rb'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', re.S)
for path in sys.argv[1:]:
    try:
        data = open(path, 'rb').read()
    except OSError:
        continue
    for m in pat.finditer(data):
        try:
            der = base64.b64decode(re.sub(rb'\s', b'', m.group(1)))
        except Exception:
            continue
        print(hashlib.sha256(der).hexdigest().upper() + "\t" + path)
PYEOF
    else
        local f d
        for f in "$@"; do
            [ -f "$f" ] || continue
            d="$(mktemp -d "${TMPDIR:-/tmp}/fix-ca-split.XXXXXX")"
            "$OPENSSL" crl2pkcs7 -nocrl -certfile "$f" 2>/dev/null \
                | "$OPENSSL" pkcs7 -print_certs 2>/dev/null > "$d/all.pem"
            [ -s "$d/all.pem" ] || cp "$f" "$d/all.pem"
            awk -v d="$d" '/BEGIN CERTIFICATE/{n++} n>0{print > (d "/c_" n ".pem")}' "$d/all.pem"
            local c h
            for c in "$d"/c_*.pem; do
                [ -f "$c" ] || continue
                h="$("$OPENSSL" x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null \
                     | sed 's/.*=//; s/://g')"
                [ -n "$h" ] && printf '%s\t%s\n' "$h" "$f"
            done
            rm -rf "$d"
        done
    fi
}

# bundle_bad_roots <file>  -> prints the names of compromised roots found
bundle_bad_roots() {
    local f="$1" fps line fp
    fps="$(fingerprints_of_bundle "$f" 2>/dev/null | awk -F'\t' -v p="$f" '$2==p{print $1}')"
    [ -n "$fps" ] || return 0
    while IFS= read -r fp; do
        case " $BAD_ROOT_FPS " in
            *" $fp "*) case "$fp" in
                           "$FP_AAA") printf '%s\n' "AAA Certificate Services";;
                           "$FP_EMSIGN_G3") printf '%s\n' "emSign ECC Root CA - G3";;
                       esac ;;
        esac
    done <<EOF
$fps
EOF
}

# count_certs <file>
count_certs() {
    local f="$1"
    if [ -n "$PYTHON" ]; then
        "$PYTHON" -c '
import re,sys
try: d=open(sys.argv[1],"rb").read()
except OSError: print(0); raise SystemExit
print(len(re.findall(rb"-----BEGIN CERTIFICATE-----",d)))
' "$f" 2>/dev/null
    else
        grep -c -- '-----BEGIN CERTIFICATE-----' "$f" 2>/dev/null
    fi
}

# -----------------------------------------------------------------------------
# Network probes
# -----------------------------------------------------------------------------

# probe_curl_cafile <cafile> -> 0 when the client TRUSTS the malicious chain
probe_curl_cafile() {
    local cafile="$1"
    [ "$OFFLINE" -eq 1 ] && return 3
    [ -n "$CURL" ] || return 3
    local url
    for url in $PROBE_URLS; do
        if "$CURL" -sS -o /dev/null --max-time "$TIMEOUT" --cacert "$cafile" "$url" >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

# probe_python_cafile <python> <cafile> -> 0 when that interpreter TRUSTS the chain
probe_python_cafile() {
    local py="$1" cafile="$2"
    [ "$OFFLINE" -eq 1 ] && return 3
    [ -x "$py" ] || return 3
    "$py" - "$cafile" <<'PYEOF' >/dev/null 2>&1
import socket, ssl, sys
cafile = sys.argv[1]
host = "dv-g3b-emudhra.we-have-a-problem.com"
try:
    ctx = ssl.create_default_context(cafile=cafile)
except Exception:
    sys.exit(3)
try:
    with socket.create_connection((host, 443), timeout=10) as s:
        with ctx.wrap_socket(s, server_hostname=host):
            pass
except Exception:
    sys.exit(1)
sys.exit(0)
PYEOF
}

# probe_keychain -> 0 when the macOS keychain still trusts the chain
probe_keychain() {
    [ "$OFFLINE" -eq 1 ] && return 3
    command -v security >/dev/null 2>&1 || return 3
    local out
    out="$(security verify-cert -p ssl "https://dv-g3b-emudhra.we-have-a-problem.com/" 2>&1)"
    case "$out" in
        *"verification successful"*) return 0 ;;
        *CSSMERR*|*revoked*|*fail*) return 1 ;;
        *) return 3 ;;
    esac
}

# -----------------------------------------------------------------------------
# Assess one PEM bundle (host trust stores).
#   assess_bundle <section> <label> <path> [python-for-probe] [indent]
# One result line per bundle; the affected detail is appended inline.
# -----------------------------------------------------------------------------
bundle_affected_detail() {  # <path> <python> <bad-root-names>
    local path="$1" py="${2:-}" names="$3" joined rc=3
    joined="$(printf '%s\n' "$names" | awk 'NF{if(n++)printf ", "; printf "%s", $0}')"
    if [ -n "$py" ] && [ -x "$py" ]; then
        probe_python_cafile "$py" "$path"; rc=$?
    elif [ -n "$CURL" ]; then
        probe_curl_cafile "$path"; rc=$?
    fi
    case "$rc" in
        0) printf 'trusts %s; live probe ACCEPTED a forged certificate\n' "$joined" ;;
        1) printf 'trusts %s; live probe rejected the certificate\n' "$joined" ;;
        *) printf 'trusts %s\n' "$joined" ;;
    esac
}

assess_bundle() {
    local section="$1" label="$2" path="$3" py="${4:-}" indent="${5:-2}"
    [ -f "$path" ] || return 0

    begin_check "$indent" "$label"
    local names; names="$(bundle_bad_roots "$path")"
    if [ -n "$names" ]; then
        local detail; detail="$(bundle_affected_detail "$path" "$py" "$names")"
        end_check "$C_RED" FAIL "$label $DASH $detail" "$indent"
        record AFFECTED "$section" "$path" "$detail"
    else
        end_check "$C_GREEN" " ok " "$label" "$indent"
        record OK "$section" "$path" "$(count_certs "$path") certs"
    fi
}

# -----------------------------------------------------------------------------
# Trust store discovery
# -----------------------------------------------------------------------------

discover_conda() {
    local c
    for c in "${CONDA_EXE:-}" \
             "$(command -v conda 2>/dev/null || true)" \
             /usr/local/miniconda3/bin/conda /usr/local/anaconda3/bin/conda \
             /opt/miniconda3/bin/conda /opt/anaconda3/bin/conda \
             /opt/homebrew/Caskroom/miniconda/base/bin/conda \
             "$HOME/miniconda3/bin/conda" "$HOME/anaconda3/bin/conda" \
             "$HOME/miniforge3/bin/conda" "$HOME/mambaforge/bin/conda"; do
        [ -n "$c" ] && [ -x "$c" ] && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}

conda_env_list() {
    local conda="$1"
    "$conda" env list --json 2>/dev/null | "$PYTHON" -c '
import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    raise SystemExit(1)
for e in d.get("envs", []):
    print(e)
' 2>/dev/null
}

# -----------------------------------------------------------------------------
# ASSESS
# -----------------------------------------------------------------------------
assess_system() {
    hdr "1. macOS system trust store"
    note "used by curl, git, perl, ruby, openssl and the built-in python3"
    assess_bundle "system" "/etc/ssl/cert.pem" /etc/ssl/cert.pem "" 2

    begin_check 2 "macOS keychain"
    local krc=3
    probe_keychain; krc=$?
    case "$krc" in
        0) end_check "$C_RED" FAIL "macOS keychain $DASH still trusts the compromised chain" 2
           record AFFECTED "keychain" "System.keychain" "still trusts the chain" ;;
        1) end_check "$C_GREEN" " ok " "macOS keychain $DASH Apple already blocks the certificates" 2
           record OK "keychain" "System.keychain" "blocked" ;;
        *) end_check "$C_YELLOW" " warn " "macOS keychain $DASH not determined (offline?)" 2
           record SKIP "keychain" "System.keychain" "not tested" ;;
    esac
}

# conda_pkg_versions <env> -> "certifi-..., ca-certificates-..."
conda_pkg_versions() {
    local env="$1" out="" m j
    for m in certifi ca-certificates; do
        j="$(ls "$env/conda-meta/" 2>/dev/null | grep -E "^${m}-" | head -1)"
        [ -n "$j" ] && out="${out}${out:+, }${j%.json}"
    done
    printf '%s\n' "$out"
}

# conda_env_name <conda> <envpath> -> "base" or the directory name
conda_env_name() {
    local conda="$1" env="$2" root
    root="$(cd "$(dirname "$conda")/.." 2>/dev/null && pwd -P)"
    if [ -n "$root" ] && [ "$(cd "$env" 2>/dev/null && pwd -P)" = "$root" ]; then
        printf 'base\n'
    else
        basename "$env"
    fi
}

# conda_bundle_globs <env> -> prints every CA bundle path in the environment
conda_bundle_globs() {
    local env="$1" f real seen=""
    for f in "$env"/lib/python*/site-packages/certifi/cacert.pem \
             "$env"/ssl/cacert.pem "$env"/ssl/cert.pem; do
        [ -f "$f" ] || continue
        real="$(readlink -f "$f" 2>/dev/null || printf '%s' "$f")"
        case " $seen " in *" $real "*) continue ;; esac   # skip symlink aliases
        seen="$seen $real"
        printf '%s\n' "$real"
    done
}

assess_homebrew() {
    local prefix=""
    command -v brew >/dev/null 2>&1 && prefix="$(brew --prefix 2>/dev/null || true)"
    [ -n "$prefix" ] || prefix="/opt/homebrew"
    [ -d "$prefix/etc" ] || return 0

    hdr "2. Homebrew trust stores"
    local f
    for f in "$prefix/etc/ca-certificates/cert.pem" \
             "$prefix/etc/openssl@3/cert.pem" \
             "$prefix/etc/openssl/cert.pem" \
             "$prefix/etc/openssl@1.1/cert.pem"; do
        [ -e "$f" ] || continue
        assess_bundle "homebrew" "$f" "$f" "" 2
    done
}

assess_python_host() {
    hdr "3. Python interpreters and pip"
    local py seen=""
    for py in /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3 \
              "$(command -v python3 2>/dev/null || true)"; do
        [ -n "$py" ] && [ -x "$py" ] || continue
        local real; real="$(readlink -f "$py" 2>/dev/null || printf '%s' "$py")"
        case " $seen " in *" $real "*) continue ;; esac
        seen="$seen $real"
        local cafile=""
        cafile="$("$py" -c 'import certifi;print(certifi.where())' 2>/dev/null || true)"
        if [ -n "$cafile" ] && [ -f "$cafile" ]; then
            assess_bundle "python" "certifi of $py" "$cafile" "$py" 2
        else
            begin_check 2 "certifi of $py"
            end_check "$C_YELLOW" " warn " "certifi of $py $DASH no certifi module" 2
            record SKIP "python" "$py" "no certifi module"
        fi
    done

    local pipconf_user="${XDG_CONFIG_HOME:-$HOME/.config}/pip/pip.conf"
    local pipconf_system="/Library/Application Support/pip/pip.conf"
    begin_check 2 "pip configuration"
    if [ -f "$pipconf_user" ]; then
        end_check "$C_GREEN" " ok " "pip.conf: $pipconf_user" 2
        record OK "pip" "$pipconf_user" "present"
    elif [ -f "$pipconf_system" ]; then
        end_check "$C_GREEN" " ok " "pip.conf: $pipconf_system" 2
        record OK "pip" "$pipconf_system" "present"
    elif [ "${PIP_CERT:-}" = "/etc/ssl/cert.pem" ]; then
        end_check "$C_GREEN" " ok " "PIP_CERT already points at /etc/ssl/cert.pem" 2
        record OK "pip" "PIP_CERT" "set"
    else
        end_check "$C_YELLOW" " warn " "pip uses its own bundled certifi (no pip.conf, PIP_CERT unset)" 2
        record WARN "pip" "$pipconf_user" "not configured"
    fi
}

assess_conda() {
    local conda; conda="$(discover_conda)" || {
        hdr "4. conda environments"
        warn "no conda installation found $DASH skipping"
        record SKIP "conda" "-" "conda not found"
        return 0
    }

    hdr "4. conda environments"
    local cv; cv="$("$conda" --version 2>/dev/null | head -1)"
    note "conda: $conda  ($cv)"

    local envs; envs="$(conda_env_list "$conda")"
    if [ -z "$envs" ]; then
        warn "could not enumerate conda environments"
        record SKIP "conda" "$conda" "enumeration failed"
        return 0
    fi

    local env count=0
    while IFS= read -r env; do
        [ -n "$env" ] || continue
        count=$((count + 1))
        local name; name="$(conda_env_name "$conda" "$env")"
        begin_check 2 "conda env: $name"

        # scan every CA bundle in this environment (no network yet) so the
        # whole environment is reported as one compact result
        local found=0 affected="" details="" f names d
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            found=$((found + 1))
            names="$(bundle_bad_roots "$f")"
            [ -n "$names" ] || continue
            d="$(bundle_affected_detail "$f" "$env/bin/python" "$names")"
            affected="${affected}${f}
"
            details="${details}${f}|${d}
"
        done <<EOF
$(conda_bundle_globs "$env")
EOF

        if [ "$found" -eq 0 ]; then
            end_check "$C_YELLOW" " warn " "conda env: $name $DASH no CA bundle found" 2
            record SKIP "conda:$name" "$env" "no CA bundle"
            continue
        fi

        if [ -z "$affected" ]; then
            end_check "$C_GREEN" " ok " "conda env: $name" 2
            record OK "conda:$name" "$env" "$found CA bundle(s) clean"
            continue
        fi

        local nb; nb="$(printf '%s' "$affected" | grep -c .)"
        end_check "$C_RED" FAIL "conda env: $name $DASH $nb of $found CA bundle(s) affected" 2
        local versions; versions="$(conda_pkg_versions "$env")"
        [ -n "$versions" ] && printf '      %sinstalled: %s%s\n' "$C_DIM" "$versions" "$C_RESET"

        printf '%s' "$details" | while IFS='|' read -r f d; do
            [ -n "$f" ] || continue
            printf '      %s%s%s\n' "$C_RED" "$f" "$C_RESET"
            printf '        %s%s%s\n' "$C_DIM" "$d" "$C_RESET"
            record AFFECTED "conda:$name" "$f" "$d"
        done
    done <<EOF
$envs
EOF
    note "environments inspected: $count"
}

# -----------------------------------------------------------------------------
# APPLY: bundle surgery (fingerprint exact removal)
# -----------------------------------------------------------------------------
# Removes the compromised roots from a PEM bundle while preserving every other
# certificate and all comment/header lines. Unlike a subject-name regex this
# cannot delete the wrong certificate (there are several eMudhra and Comodo
# roots that are NOT affected).
surgery_remove_roots() {
    local src="$1" dst="$2"
    if [ -z "$PYTHON" ]; then
        printf 'surgery_remove_roots: python3 is required for exact certificate removal\n' >&2
        return 1
    fi
    "$PYTHON" - "$src" "$dst" "$FP_AAA" "$FP_EMSIGN_G3" <<'PYEOF'
import base64, hashlib, re, sys

src, dst = sys.argv[1], sys.argv[2]
bad = set(sys.argv[3:])

with open(src, "rb") as fh:
    data = fh.read()

certpat = re.compile(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----[ \t]*\r?\n?', re.S)

def fp(block):
    body = re.search(rb'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', block, re.S).group(1)
    try:
        der = base64.b64decode(re.sub(rb'\s', b'', body))
    except Exception:
        return None
    return hashlib.sha256(der).hexdigest().upper()

# ---- split into segments at "### " header lines (OpenBSD/macOS style) -------
parts = re.split(rb'(?m)^(?=### )', data)
out = []
removed = 0
for part in parts:
    certs = certpat.findall(part)
    if certs:
        kept = [c for c in certs if fp(c) not in bad]
        dropped = len(certs) - len(kept)
        if dropped == len(certs) and not kept:
            # whole segment is compromised -> drop header + body
            removed += dropped
            continue
        if dropped:
            # remove only the compromised PEMs together with the descriptive
            # block that belongs to them (certifi "# ..." comments or the
            # OpenBSD "=== subject" dumps), so no orphaned text is left behind.
            for c in certs:
                if fp(c) not in bad:
                    continue
                removed += 1
                idx = part.find(c)
                head = part[:idx]
                tail = part[idx + len(c):]

                # OpenBSD/macOS style: truncate at the last "=== " dump block
                dumps = [m.start() for m in re.finditer(rb'(?m)^=== ', head)]
                if dumps:
                    head = head[:dumps[-1]]

                # OpenSSL/conda style: drop a trailing "Name\n======" title block
                head = re.sub(
                    rb'(?m)^[^\n=][^\n]*\n={3,}[ \t]*\n[ \t\r\n]*\Z', b'', head)

                # certifi/Mozilla style: drop the trailing per-certificate
                # comment block. Single "#" only - "##" global headers and
                # "### " section headers must survive, otherwise a section
                # header would be deleted while its unaffected certificates
                # are kept.
                lines = head.split(b'\n')
                while lines and not lines[-1].strip():
                    lines.pop()
                while lines and lines[-1].lstrip().startswith(b'#') \
                        and not lines[-1].lstrip().startswith(b'##'):
                    lines.pop()
                head = b'\n'.join(lines)

                if head:
                    head = head.rstrip(b' \t\r\n') + b'\n\n'

                part = head + tail.lstrip(b'\r\n')
    out.append(part)

new = b''.join(out)
if removed and not new.endswith(b'\n'):
    new += b'\n'
with open(dst, "wb") as fh:
    fh.write(new)
print(removed)
PYEOF
}

# -----------------------------------------------------------------------------
# Backups and safe installation
#
# The original file is never removed and never written in place: a backup is
# taken first, and the replacement is written next to the target and moved
# into place with an atomic rename. An interrupted run therefore leaves either
# the complete old file or the complete new one, never a truncated bundle.
# -----------------------------------------------------------------------------
file_sha256() {
    if [ -n "$PYTHON" ]; then
        "$PYTHON" -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1" 2>/dev/null
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        cksum "$1" 2>/dev/null | awk '{print $1"-"$2}'
    fi
}

# Set by do_snapshot_all: lines of "<path>\t<backup>" so that a file
# snapshotted earlier in the same run is not backed up a second time.
SNAPSHOT_INDEX=""
snapshot_lookup() {
    local r
    [ -n "$SNAPSHOT_INDEX" ] || return 1
    r="$(printf '%s\n' "$SNAPSHOT_INDEX" | awk -F'\t' -v k="$1" '$1==k{print $2; exit}')"
    [ -n "$r" ] || return 1
    printf '%s\n' "$r"
}

# backup_file <path> - copy <path> to <path>.bak.<timestamp> and verify it.
# Falls back to sudo for root owned files and returns non-zero when no
# verified backup could be made, so callers can refuse to modify the file.
# Sets LAST_BACKUP on success.
LAST_BACKUP=""
backup_file() {
    local f="$1" ts bak ok=0 src_sum bak_sum snap
    ts="$(date +%Y%m%d-%H%M%S)"
    bak="$f.bak.$ts"

    if [ "$DRY_RUN" -eq 1 ]; then
        note "would back up $f -> $bak"
        LAST_BACKUP="$bak"
        return 0
    fi

    # reuse the snapshot taken earlier in this run, if there is one
    if snap="$(snapshot_lookup "$f")"; then
        LAST_BACKUP="$snap"
        note "backup: $snap (taken at the start of this run)"
        return 0
    fi

    # never clobber a backup that is already there
    if [ -e "$bak" ]; then
        bak="$bak.$$"
    fi

    cp -p "$f" "$bak" 2>/dev/null && ok=1
    [ "$ok" -eq 1 ] || { cp "$f" "$bak" 2>/dev/null && ok=1; }
    if [ "$ok" -eq 0 ] && command -v sudo >/dev/null 2>&1; then
        sudo cp -p "$f" "$bak" 2>/dev/null && ok=1
    fi

    if [ "$ok" -eq 0 ] || [ ! -s "$bak" ]; then
        bad "could not create a backup of $f - refusing to modify it"
        return 1
    fi

    # it must be byte for byte the same file, not an empty or partial copy
    src_sum="$(file_sha256 "$f")"
    bak_sum="$(file_sha256 "$bak")"
    if [ -n "$src_sum" ] && [ "$src_sum" != "$bak_sum" ]; then
        bad "backup of $f does not match the original - refusing to modify it"
        return 1
    fi

    LAST_BACKUP="$bak"
    note "backup: $bak"
    return 0
}

# install_file_atomic <src> <dst>
install_file_atomic() {
    local src="$1" dst="$2" new mode owner
    new="$dst.new.$$"
    mode="$(stat -f '%Lp' "$dst" 2>/dev/null || printf '644')"
    owner="$(stat -f '%Su:%Sg' "$dst" 2>/dev/null || true)"

    if cp "$src" "$new" 2>/dev/null; then
        chmod "$mode" "$new" 2>/dev/null
        if mv -f "$new" "$dst"; then
            return 0
        fi
        rm -f "$new"
        return 1
    fi

    command -v sudo >/dev/null 2>&1 || return 1
    sudo cp "$src" "$new" 2>/dev/null || { sudo rm -f "$new" 2>/dev/null; return 1; }
    sudo chmod "$mode" "$new" 2>/dev/null
    if ! sudo mv -f "$new" "$dst"; then
        sudo rm -f "$new" 2>/dev/null
        return 1
    fi
    [ -n "$owner" ] && sudo chown "$owner" "$dst" 2>/dev/null
    return 0
}

# find_newest_backup <path> - newest <path>.bak* or empty
find_newest_backup() {
    local f="$1" b newest=""
    for b in "$f".bak "$f".bak.*; do
        [ -e "$b" ] || continue
        if [ -z "$newest" ] || [ "$b" -nt "$newest" ]; then
            newest="$b"
        fi
    done
    [ -n "$newest" ] && printf '%s\n' "$newest"
    return 0
}

# restore_file <path> - put the newest verified backup back in place
restore_file() {
    local f="$1" b
    b="$(find_newest_backup "$f")"
    if [ -z "$b" ]; then
        return 2
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        note "would restore $f from $b"
        return 0
    fi
    # keep the current file too, in case the restore is not wanted
    backup_file "$f" >/dev/null 2>&1 || true
    if install_file_atomic "$b" "$f"; then
        ok "restored $f from $b"
        return 0
    fi
    bad "could not restore $f from $b"
    return 1
}

# every CA bundle the script knows about
all_bundle_paths() {
    printf '%s\n' /etc/ssl/cert.pem
    local conda env
    conda="$(discover_conda)" || return 0
    conda_env_list "$conda" | while IFS= read -r env; do
        [ -n "$env" ] || continue
        conda_bundle_globs "$env"
    done
}

apply_system() {
    hdr "Fix 1: /etc/ssl/cert.pem (hardens curl, git, perl, ruby, openssl, python3)"
    local f=/etc/ssl/cert.pem
    [ -f "$f" ] || { warn "$f not present - skipping"; return 0; }
    local names; names="$(bundle_bad_roots "$f")"
    if [ -z "$names" ]; then
        ok "already clean, nothing to do"
        record OK "system" "$f" "already clean"
        return 0
    fi
    info "found: $(printf '%s\n' "$names" | awk 'NF{if(n++)printf ", "; printf "%s", $0}')"

    local tmp; tmp="$(mktemp "${TMPDIR:-/tmp}/cert.pem.XXXXXX")"
    local removed; removed="$(surgery_remove_roots "$f" "$tmp" 2>/dev/null)"
    local before after
    before="$(count_certs "$f")"; after="$(count_certs "$tmp")"
    info "certificates: $before -> $after (removed ${removed:-0})"

    if [ "${after:-0}" -lt 100 ] || [ "${removed:-0}" -lt 1 ]; then
        bad "refusing to write: sanity check failed (removed ${removed:-0}, $after certs left)"
        rm -f "$tmp"; record WARN "system" "$f" "surgery sanity check failed"; return 1
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        note "would install hardened bundle to $f (needs sudo)"
        rm -f "$tmp"; record SKIP "system" "$f" "dry-run"; return 0
    fi

    backup_file "$f" || { rm -f "$tmp"; record WARN "system" "$f" "no backup could be created"; return 1; }
    local bak="$LAST_BACKUP"
    if ! install_file_atomic "$tmp" "$f"; then
        bad "failed to write $f"
        rm -f "$tmp"; record WARN "system" "$f" "write failed"; return 1
    fi
    rm -f "$tmp"

    # verify the write actually took effect before claiming success
    if [ -n "$(bundle_bad_roots "$f")" ]; then
        bad "$f still contains a compromised root after writing"
        if [ -n "$bak" ]; then
            install_file_atomic "$bak" "$f" && note "restored the original from $bak"
        fi
        record WARN "system" "$f" "write did not take effect, restored from backup"
        return 1
    fi

    ok "$f hardened ($before -> $(count_certs "$f") certificates)"
    note "original kept at $bak"
    record FIXED "system" "$f" "removed $removed compromised roots (backup: $bak)"
}

apply_pip() {
    hdr "Fix 2: pip / python"
    [ -n "$PYTHON" ] || { warn "no python3 found - skipping"; return 0; }

    # 2a. user level pip.conf (PEP 668 safe, no sudo, survives python upgrades)
    local pipconf="${XDG_CONFIG_HOME:-$HOME/.config}/pip/pip.conf"
    local marker="# managed by fix-certificates.sh"
    if [ -f "$pipconf" ] && grep -qF "$marker" "$pipconf" 2>/dev/null; then
        ok "pip.conf already configured: $pipconf"
        record OK "pip" "$pipconf" "already configured"
    elif [ "$DRY_RUN" -eq 1 ]; then
        note "would write $pipconf with 'cert = /etc/ssl/cert.pem'"
        record SKIP "pip" "$pipconf" "dry-run"
    else
        mkdir -p "$(dirname "$pipconf")"
        if [ -f "$pipconf" ]; then
            cp -p "$pipconf" "$pipconf.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
            printf '\n%s\n[global]\ncert = /etc/ssl/cert.pem\n' "$marker" >> "$pipconf"
        else
            printf '%s\n[global]\ncert = /etc/ssl/cert.pem\n' "$marker" > "$pipconf"
        fi
        ok "configured $pipconf"
        record FIXED "pip" "$pipconf" "cert=/etc/ssl/cert.pem"
    fi

    # 2b. PIP_CERT for every interpreter, so pip in venvs and scripts also uses
    #     the hardened bundle. The upstream advice appends to the stdlib
    #     sitecustomize.py; on Homebrew systems that file is owned by Homebrew,
    #     so we only create one when it is absent and otherwise use PIP_CERT
    #     via a small, clearly marked append.
    local stdlib sitecustomize
    stdlib="$("$PYTHON" -c 'import sysconfig;print(sysconfig.get_path("stdlib"))' 2>/dev/null)"
    if [ -n "$stdlib" ]; then
        sitecustomize="$stdlib/sitecustomize.py"
        local line='import os; os.environ.setdefault("PIP_CERT", "/etc/ssl/cert.pem")'
        if [ -f "$sitecustomize" ] && grep -qF 'PIP_CERT' "$sitecustomize" 2>/dev/null; then
            ok "PIP_CERT already set in $sitecustomize"
            record OK "pip" "$sitecustomize" "already configured"
        elif [ "$DRY_RUN" -eq 1 ]; then
            note "would set PIP_CERT in $sitecustomize"
            record SKIP "pip" "$sitecustomize" "dry-run"
        else
            local need_sudo=0
            [ -w "$sitecustomize" ] || [ ! -e "$sitecustomize" ] || need_sudo=1
            [ -w "$stdlib" ] || need_sudo=1
            if [ "$need_sudo" -eq 1 ]; then
                if ! sudo -n true 2>/dev/null && [ "$ASSUME_YES" -eq 0 ]; then
                    warn "sudo required to write $sitecustomize"
                fi
                if [ -f "$sitecustomize" ]; then
                    printf '\n# managed by fix-certificates.sh\n%s\n' "$line" | sudo tee -a "$sitecustomize" >/dev/null \
                        || { warn "could not update $sitecustomize"; record WARN "pip" "$sitecustomize" "write failed"; return 0; }
                else
                    printf '# managed by fix-certificates.sh\n%s\n' "$line" | sudo tee "$sitecustomize" >/dev/null \
                        || { warn "could not create $sitecustomize"; record WARN "pip" "$sitecustomize" "write failed"; return 0; }
                fi
                sudo chmod 644 "$sitecustomize" 2>/dev/null
            else
                if [ -f "$sitecustomize" ]; then
                    printf '\n# managed by fix-certificates.sh\n%s\n' "$line" >> "$sitecustomize"
                else
                    printf '# managed by fix-certificates.sh\n%s\n' "$line" > "$sitecustomize"
                fi
                chmod 644 "$sitecustomize" 2>/dev/null
            fi
            ok "PIP_CERT configured in $sitecustomize"
            record FIXED "pip" "$sitecustomize" "PIP_CERT=/etc/ssl/cert.pem"
        fi
    fi
}

# Try to update a conda env with conda itself (the clean fix).
conda_update_env() {
    local conda="$1" env="$2" name="$3"
    # Prefer conda-forge when the environment already uses it, because its
    # ca-certificates package tracks the Mozilla bundle closely.
    local ch="defaults"
    if ls "$env/conda-meta/" 2>/dev/null | grep -q 'conda-forge'; then
        ch="conda-forge"
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        note "  would run: conda install -p $env -c $ch certifi ca-certificates"
        return 2
    fi
    info "  conda install -p $(basename "$env") -c $ch certifi ca-certificates"
    if CONDA_NO_PLUGINS=true "$conda" install -y -p "$env" --override-channels \
            -c "$ch" "certifi>=2026.10.19" "ca-certificates>=2026.10.19" 2>&1 | tail -5; then
        return 0
    fi
    return 1
}

# Last resort: patch the certificates inside the bundle directly.
conda_patch_env_bundle() {
    local path; path="$(readlink -f "$1" 2>/dev/null || printf '%s' "$1")"
    local label="${2:-conda}"
    local tmp; tmp="$(mktemp "${TMPDIR:-/tmp}/ca-patch.XXXXXX")"
    local removed; removed="$(surgery_remove_roots "$path" "$tmp" 2>/dev/null)"
    local after; after="$(count_certs "$tmp")"
    if [ "${after:-0}" -lt 50 ] || [ "${removed:-0}" -lt 1 ]; then
        warn "  refusing to patch $path (removed ${removed:-0}, only ${after:-0} certs would remain)"
        rm -f "$tmp"; return 1
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        note "  would remove $removed compromised root(s) from $path"
        rm -f "$tmp"; return 0
    fi
    backup_file "$path" || { rm -f "$tmp"; return 1; }
    local bak="$LAST_BACKUP"
    if ! install_file_atomic "$tmp" "$path"; then
        warn "  failed to write $path"; rm -f "$tmp"; return 1
    fi
    rm -f "$tmp"
    if [ -n "$(bundle_bad_roots "$path")" ]; then
        warn "  $path still contains a compromised root after patching"
        [ -n "$bak" ] && install_file_atomic "$bak" "$path" && note "  restored the original from $bak"
        return 1
    fi
    ok "  patched in place: $path (removed $removed)"
    note "  original kept at $bak"
    record FIXED "conda:$label" "$path" "patched in place, removed $removed root(s) (backup: $bak)"
    return 0
}

apply_conda() {
    local conda; conda="$(discover_conda)" || {
        hdr "Fix 3: conda environments"; warn "no conda installation found - skipping"
        return 0
    }
    hdr "Fix 3: conda environments"
    local envs; envs="$(conda_env_list "$conda")"
    if [ -z "$envs" ]; then
        warn "could not enumerate conda environments - skipping"
        return 0
    fi

    local env
    while IFS= read -r env; do
        [ -n "$env" ] || continue
        local name; name="$(conda_env_name "$conda" "$env")"

        # collect affected bundles in this env (newline separated: paths may
        # contain spaces, so never rely on word splitting)
        local affected="" f names
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            names="$(bundle_bad_roots "$f")"
            [ -n "$names" ] && affected="${affected}${f}
"
        done <<EOF
$(conda_bundle_globs "$env")
EOF
        [ -n "$affected" ] || { ok "$name: nothing to do"; continue; }

        sub "env: $name"
        printf '%s' "$affected" | while IFS= read -r f; do
            [ -n "$f" ] && info "affected: $f"
        done

        local urc=0
        conda_update_env "$conda" "$env" "$name"; urc=$?
        case "$urc" in
            0) ;;   # attempted
            2) ;;   # dry run
            *) warn "  conda update did not complete" ;;
        esac

        # re-check; patch directly for anything conda could not fix
        printf '%s' "$affected" | while IFS= read -r f; do
            [ -n "$f" ] || continue
            if [ -n "$(bundle_bad_roots "$f")" ]; then
                if [ "$DRY_RUN" -eq 1 ]; then
                    note "  would patch in place if still affected: $f"
                else
                    warn "  still affected after conda update: $f"
                    conda_patch_env_bundle "$f" "$name"
                fi
            else
                ok "  fixed by conda: $f"
                record FIXED "conda:$name" "$f" "updated by conda"
            fi
        done
    done <<EOF
$envs
EOF
}

# -----------------------------------------------------------------------------
# REPORT
# -----------------------------------------------------------------------------
section_label() {
    case "$1" in
        system)   printf 'macOS system trust store\n' ;;
        keychain) printf 'macOS keychain\n' ;;
        homebrew) printf 'Homebrew\n' ;;
        python)   printf 'Python interpreters\n' ;;
        pip)      printf 'pip / python configuration\n' ;;
        conda:*)  printf 'conda env: %s\n' "${1#conda:}" ;;
        *)        printf '%s\n' "$1" ;;
    esac
}

# Compact list of what apply is about to change, shown before the prompts.
print_affected_targets() {
    local n; n="$(count_status AFFECTED)"
    printf '  About to modify %s%d%s affected trust store(s):\n' "$C_BOLD" "$n" "$C_RESET"
    local last="" st sec tgt det
    while IFS=$'\t' read -r st sec tgt det; do
        [ "$st" = "AFFECTED" ] || continue
        if [ "$sec" != "$last" ]; then
            printf '    %s%s%s\n' "$C_BOLD" "$(section_label "$sec")" "$C_RESET"
            last="$sec"
        fi
        printf '      %s\n' "$tgt"
    done < "$RESULTS_FILE"
}

# Loud, grouped list of everything that is still affected.
print_attention() {
    local n; n="$(count_status AFFECTED)"
    [ "${n:-0}" -gt 0 ] || return 0

    printf '\n  %s%s!! ATTENTION !!%s %s%d trust store(s) still trust the compromised CA%s\n' \
        "$C_BOLD" "$C_RED" "$C_RESET" "$C_BOLD" "$n" "$C_RESET"
    printf '  %s%s%s\n' "$C_DIM" "--------------------------------------------------------------------" "$C_RESET"

    local last="" st sec tgt det
    while IFS=$'\t' read -r st sec tgt det; do
        [ "$st" = "AFFECTED" ] || continue
        if [ "$sec" != "$last" ]; then
            printf '\n    %s%s%s\n' "$C_BOLD" "$(section_label "$sec")" "$C_RESET"
            last="$sec"
        fi
        printf '      %s%s %s%s\n' "$C_RED" "$BULLET" "$tgt" "$C_RESET"
        [ -n "$det" ] && printf '        %s%s%s\n' "$C_DIM" "$det" "$C_RESET"
    done < "$RESULTS_FILE"
}

print_summary() {
    local affected okc warnc fixed skip
    affected="$(count_status AFFECTED)"
    okc="$(count_status OK)"
    warnc="$(count_status WARN)"
    fixed="$(count_status FIXED)"
    skip="$(count_status SKIP)"
    if [ -n "$REMEDIATION_FILE" ]; then
        fixed=$((fixed + $(count_status_in "$REMEDIATION_FILE" FIXED)))
    fi

    hdr "Summary"
    if [ "${affected:-0}" -gt 0 ]; then
        printf '  %s%saffected : %s%s\n' "$C_BOLD" "$C_RED" "$affected" "$C_RESET"
    else
        printf '  affected : 0\n'
    fi
    printf '  clean    : %s\n' "$okc"
    [ "$fixed" -gt 0 ] && printf '  fixed    : %s%s%s\n' "$C_GREEN" "$fixed" "$C_RESET"
    [ "$warnc" -gt 0 ] && printf '  warnings : %s\n' "$warnc"
    [ "$skip" -gt 0 ] && printf '  skipped  : %s\n' "$skip"

    print_attention

    if [ "$JSON_OUT" -eq 1 ]; then
        printf '\n'
        "$PYTHON" - "$RESULTS_FILE" "${REMEDIATION_FILE:-}" >&3 <<'PYEOF'
import json, sys

def read_rows(path):
    rows = []
    if not path:
        return rows
    try:
        fh = open(path)
    except OSError:
        return rows
    for line in fh:
        parts = line.rstrip("\n").split("\t")
        while len(parts) < 4:
            parts.append("")
        rows.append({"status": parts[0], "section": parts[1], "target": parts[2], "detail": parts[3]})
    return rows

rows = read_rows(sys.argv[1])
remediation = read_rows(sys.argv[2])
summary = {}
for r in rows:
    summary[r["status"]] = summary.get(r["status"], 0) + 1
fixed = sum(1 for r in remediation if r["status"] == "FIXED")
if fixed:
    summary["FIXED"] = fixed
print(json.dumps({"summary": summary, "results": rows, "remediation": remediation}, indent=2))
PYEOF
    fi
}

# -----------------------------------------------------------------------------
# RESTORE
# -----------------------------------------------------------------------------
restore_all() {
    hdr "Restoring trust stores from their backups"
    note "/etc/ssl/cert.pem and every conda environment bundle are checked"

    local f n=0 missing=0 failed=0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        restore_file "$f"
        case $? in
            0) n=$((n + 1)) ;;
            2) missing=$((missing + 1)) ;;
            *) failed=$((failed + 1)) ;;
        esac
    done <<EOF
$(all_bundle_paths)
EOF

    hdr "Summary"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would restore : %s\n' "$n"
    else
        printf '  restored : %s\n' "$n"
    fi
    [ "$missing" -gt 0 ] && printf '  no backup: %s\n' "$missing"
    [ "$failed" -gt 0 ] && printf '  failed   : %s%s%s\n' "$C_RED" "$failed" "$C_RESET"

    if [ "$failed" -gt 0 ]; then
        exit 1
    fi
    if [ "$n" -eq 0 ]; then
        printf '\nNothing to restore.\n'
    elif [ "$DRY_RUN" -eq 1 ]; then
        printf '\nRun again without --dry-run to restore.\n'
    else
        printf '\n%sRestored %d bundle(s).%s Open a new shell to pick them up.\n' "$C_GREEN" "$n" "$C_RESET"
    fi
    exit 0
}

# -----------------------------------------------------------------------------
# BACKUP - snapshot every trust store without changing anything
# -----------------------------------------------------------------------------
BACKUPS_MADE=0
BACKUPS_FAILED=0

do_snapshot_all() {
    BACKUPS_MADE=0
    BACKUPS_FAILED=0
    SNAPSHOT_INDEX=""
    local f
    while IFS= read -r f; do
        [ -n "$f" ] && [ -f "$f" ] || continue
        if backup_file "$f"; then
            BACKUPS_MADE=$((BACKUPS_MADE + 1))
            [ -n "$LAST_BACKUP" ] && SNAPSHOT_INDEX="${SNAPSHOT_INDEX}${f}	${LAST_BACKUP}
"
        else
            BACKUPS_FAILED=$((BACKUPS_FAILED + 1))
        fi
    done <<EOF
$(all_bundle_paths)
EOF
    return 0
}
backup_all() {
    hdr "Backing up trust stores"
    do_snapshot_all

    hdr "Summary"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  would back up : %s\n' "$BACKUPS_MADE"
    else
        printf '  backed up : %s\n' "$BACKUPS_MADE"
    fi
    [ "$BACKUPS_FAILED" -gt 0 ] && printf '  failed    : %s%s%s\n' "$C_RED" "$BACKUPS_FAILED" "$C_RESET"
    exit 0
}

# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------
main() {
    printf '%s%s%s — eMudhra CA compromise checker, v%s\n' "$C_BOLD" "$SELF" "$C_RESET" "$VERSION"
    printf '%sTargets: AAA Certificate Services, emSign ECC Root CA - G3 (8 compromised intermediates)%s\n' \
        "$C_DIM" "$C_RESET"
    printf '%sMode: %s%s\n' "$C_DIM" "$ACTION" "$C_RESET"

    if [ -z "$PYTHON" ]; then
        warn "no python3 available - falling back to slow openssl scanning"
    fi

    if [ "$ACTION" = "restore" ] || [ "$ACTION" = "backup" ]; then
        if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
            if [ "$ACTION" = "restore" ]; then
                printf 'This puts the newest backup of every trust store back in place.\n'
                printf 'The current version of each file is backed up first.\n'
            else
                printf 'This copies every trust store to a .bak.<timestamp> file.\n'
                printf 'Nothing else is changed.\n'
            fi
            printf 'Continue? [y/N] '
            read -r reply
            case "$reply" in
                y|Y|yes|YES) ;;
                *) printf 'Aborted.\n'; exit 2 ;;
            esac
        fi
    fi
    [ "$ACTION" = "restore" ] && restore_all
    [ "$ACTION" = "backup" ] && backup_all

    if [ "$OFFLINE" -eq 1 ]; then
        note "offline mode: skipping live TLS probes"
    fi

    hdr "ASSESSMENT"
    assess_system
    assess_homebrew
    assess_python_host
    if [ "$DO_CONDA" -eq 1 ]; then assess_conda; else hdr "4. conda environments"; note "skipped (--no-conda)"; fi

    local affected; affected="$(count_status AFFECTED)"

    if [ "$ACTION" = "assess" ]; then
        print_summary
        if [ "$affected" -gt 0 ]; then
            printf '\n%s%d trust store(s) still trust the compromised CA.%s\n' "$C_RED" "$affected" "$C_RESET"
            printf 'Run: %s apply\n' "$SELF"
            exit 1
        fi
        printf '\n%sNothing to fix.%s\n' "$C_GREEN" "$C_RESET"
        exit 0
    fi

    # ---------------- apply ----------------
    if [ "$affected" -eq 0 ]; then
        print_summary
        printf '\n%sNothing to fix.%s\n' "$C_GREEN" "$C_RESET"
        exit 0
    fi

    hdr "REMEDIATION"

    if [ "$DRY_RUN" -eq 1 ]; then
        warn "dry run: no changes will be made"
        note "a normal run would offer to back up all trust stores first (default: yes)"
    else
        print_affected_targets

        if [ "$ASSUME_YES" -eq 0 ] && [ ! -t 0 ]; then
            warn "no terminal available to ask for confirmation"
            note "re-run with --yes to apply anyway, or add --dry-run to preview"
            exit 2
        fi

        # ---- backup prompt, recommended and defaulting to yes ----
        local do_snapshot=1
        if [ "$DO_BACKUP" -eq 0 ]; then
            do_snapshot=0
            note "--no-backup given: skipping the full snapshot"
        elif [ "$ASSUME_YES" -eq 0 ]; then
            printf '\n  %sRecommended:%s back up every trust store before changing anything.\n' \
                "$C_GREEN" "$C_RESET"
            printf '  Back up all trust stores now? [Y/n] '
            read -r reply
            case "$reply" in
                n|N|no|NO|never) do_snapshot=0 ;;
                *) do_snapshot=1 ;;
            esac
        fi

        if [ "$do_snapshot" -eq 1 ]; then
            hdr "Backup"
            do_snapshot_all
            if [ "$BACKUPS_FAILED" -gt 0 ]; then
                warn "$BACKUPS_FAILED trust store(s) could not be backed up"
            fi
            ok "$BACKUPS_MADE trust store(s) backed up"
        else
            note "no full snapshot taken; a verified backup is still written before every single file that is modified"
        fi

        # ---- go / no-go ----
        if [ "$ASSUME_YES" -eq 0 ]; then
            printf '\n  Apply the fixes now? [Y/n] '
            read -r reply
            case "$reply" in
                n|N|no|NO|never) printf 'Aborted. Nothing was modified.\n'; exit 2 ;;
            esac
        fi
    fi

    [ "$DO_SYSTEM" -eq 1 ] && apply_system
    [ "$DO_PIP" -eq 1 ] && apply_pip
    [ "$DO_CONDA" -eq 1 ] && apply_conda

    # ---- verify ----
    hdr "RE-VERIFICATION"
    REMEDIATION_FILE="$RESULTS_FILE"
    RESULTS_FILE="$(mktemp "${TMPDIR:-/tmp}/fix-ca-verify.XXXXXX")"
    assess_system
    assess_homebrew
    assess_python_host
    if [ "$DO_CONDA" -eq 1 ]; then assess_conda; fi

    affected="$(count_status AFFECTED)"
    print_summary

    if [ "$affected" -gt 0 ]; then
        printf '\n%s%d trust store(s) are STILL affected.%s\n' "$C_RED" "$affected" "$C_RESET"
        info "Restart your shell (and conda environments) and re-run: $SELF assess"
        info "Browsers and GUI apps rely on the keychain; make sure macOS is up to date."
        exit 1
    fi
    printf '\n%sRemediation complete.%s Open a new shell so every process picks up the changes.\n' \
        "$C_GREEN" "$C_RESET"
    exit 0
}

main
