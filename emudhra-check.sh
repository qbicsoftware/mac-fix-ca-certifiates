#!/bin/bash
#
# emudhra-check.sh - Audit a macOS machine's JDKs against CVE-2026-91403
#                   (compromised eMudhra intermediate CAs).
#
# Discovers every JDK it can find (system, user, SDKMAN, Homebrew, jenv,
# asdf, mise, IntelliJ) and tests whether each one still accepts TLS
# chains signed by the compromised intermediates.
#
# Usage:
#   bash emudhra-check.sh              # audit only (default)
#   bash emudhra-check.sh --inventory  # list JDKs + versions, skip network test
#   bash emudhra-check.sh --fix        # audit, then append interim blocklist
#                                      # entries to affected JDKs (makes backups)
#   bash emudhra-check.sh --json       # machine-readable result on stdout
#
# Exit codes:
#   0 = no affected JDK found     1 = at least one affected JDK
#   2 = nothing to test / error   3 = audited but results inconclusive
#
# Test hosts belong to the public disclosure site emudhra.we-have-a-problem.com
# and intentionally serve certificates from the compromised CAs.
#
set -u

#---------------------------------------------------------------------------
# Options
#---------------------------------------------------------------------------
MODE=audit
for arg in "$@"; do
  case "$arg" in
    --inventory) MODE=inventory ;;
    --fix)       MODE=fix ;;
    --json)      MODE=json ;;
    -h|--help)   sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

#---------------------------------------------------------------------------
# Colour (only when writing to a terminal)
#---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BOLD=$'\033[1m'
else
  C_RESET=; C_RED=; C_GREEN=; C_YELLOW=; C_BOLD=
fi

say()  { [ "$MODE" = json ] || printf '%s\n' "$*"; }
note() { [ "$MODE" = json ] || printf '%s\n' "$*" >&2; }

#---------------------------------------------------------------------------
# Temp workspace
#---------------------------------------------------------------------------
TMPD=$(mktemp -d 2>/dev/null) || TMPD=$(mktemp -d -t emudhra)
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT INT TERM

CANDIDATES="$TMPD/candidates"
RESULTS="$TMPD/results"
: > "$CANDIDATES"
: > "$RESULTS"

#---------------------------------------------------------------------------
# JDK discovery
#
# Each source is a glob that may or may not match; an unmatched glob stays
# literal, so every hit is validated with [ -x "$h/bin/java" ] below.
#---------------------------------------------------------------------------
add_candidates() {
  for h in "$@"; do
    [ -x "$h/bin/java" ] || continue
    # Resolve symlinks so the same JDK reached two ways is only tested once.
    real=$(cd "$h" 2>/dev/null && pwd -P) || continue
    printf '%s\n' "$real" >> "$CANDIDATES"
  done
}

# 1) Whatever this shell already points at
[ -n "${JAVA_HOME:-}" ] && add_candidates "$JAVA_HOME"

# 2) The JDK /usr/libexec/java_home reports as current
JH=$(/usr/libexec/java_home 2>/dev/null) && add_candidates "$JH"

# 3) Apple/Oracle/Adoptium-style installers (system-wide and per-user)
add_candidates /Library/Java/JavaVirtualMachines/*/Contents/Home
add_candidates "$HOME"/Library/Java/JavaVirtualMachines/*/Contents/Home

# 4) SDKMAN (skips the 'current' symlink; dedupe handles it anyway)
add_candidates "$HOME"/.sdkman/candidates/java/*/

# 5) Homebrew (Apple Silicon then Intel prefix)
for prefix in /opt/homebrew /usr/local; do
  add_candidates "$prefix"/opt/openjdk*/libexec/openjdk.jdk/Contents/Home
  add_candidates "$prefix"/Cellar/openjdk*/*/libexec/openjdk.jdk/Contents/Home
done

# 6) Other version managers
add_candidates "$HOME"/.jenv/versions/*/
add_candidates "$HOME"/.asdf/installs/java/*/
add_candidates "$HOME"/.local/share/mise/installs/java/*/

# Deduplicate and keep a stable order
sort -u "$CANDIDATES" -o "$CANDIDATES"

if [ ! -s "$CANDIDATES" ]; then
  note "No JDK installations found on this machine."
  exit 2
fi

#---------------------------------------------------------------------------
# Embedded test program
#
# Uses HttpsURLConnection so it runs on every JDK from 8 through 27.
#---------------------------------------------------------------------------
cat > "$TMPD/Check.java" <<'JAVA'
import java.net.URI;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;

public class Check {
    public static void main(String[] args) {
        int vuln = 0, ok = 0, unknown = 0;
        for (String level : new String[]{"dv", "ov", "ev"})
            for (String gen : new String[]{"g3b", "g3c"})
                for (String via : new String[]{"", "-aaa"}) {
                    String host = level + "-" + gen + via + "-emudhra.we-have-a-problem.com";
                    try {
                        HttpsURLConnection c = (HttpsURLConnection)
                            URI.create("https://" + host + "/").toURL().openConnection();
                        c.setConnectTimeout(8000);
                        c.setReadTimeout(8000);
                        c.getResponseCode();
                        System.out.println("VULNERABLE " + host);
                        vuln++;
                    } catch (SSLHandshakeException e) {
                        System.out.println("OK " + host);
                        ok++;
                    } catch (Exception e) {
                        System.out.println("INCONCLUSIVE " + host);
                        unknown++;
                    }
                }
        System.out.println("COUNTS vuln=" + vuln + " ok=" + ok + " unknown=" + unknown);
    }
}
JAVA

#---------------------------------------------------------------------------
# Helpers
#---------------------------------------------------------------------------
major_version() {
  # "21.0.12" / "1.8.0_504" / "24" -> major integer
  v=$(printf '%s' "$1" | sed -n 's/.*version "\([^"]*\)".*/\1/p')
  [ -n "$v" ] || v=$1
  case "$v" in
    1.*) printf '%s' "$v" | sed -n 's/^1\.\([0-9]*\).*/\1/p' ;;
    *)   printf '%s' "$v" | sed -n 's/^\([0-9]*\).*/\1/p' ;;
  esac
}

run_check() {
  home=$1 major=$2 out=$3
  if [ "$major" -ge 11 ] 2>/dev/null; then
    "$home/bin/java" "$TMPD/Check.java" >"$out" 2>"$TMPD/err"
  else
    # JDK 8/9/10: single-file source launch does not exist yet
    mkdir -p "$TMPD/classes"
    if "$home/bin/javac" -d "$TMPD/classes" "$TMPD/Check.java" >"$TMPD/err" 2>&1; then
      "$home/bin/java" -cp "$TMPD/classes" Check >"$out" 2>>"$TMPD/err"
    else
      : > "$out"
      return 1
    fi
  fi
}

#---------------------------------------------------------------------------
# Fetch interim blocklist data once, before the loop (only useful with --fix)
#---------------------------------------------------------------------------
if [ "$MODE" = fix ]; then
  note "Fetching impacted-intermediates.json ..."
  curl -fsS -o "$TMPD/impacted.json" \
    "https://emudhra.we-have-a-problem.com/impacted-intermediates.json" 2>/dev/null \
    || note "  could not fetch list; --fix will have nothing to apply"
fi

#---------------------------------------------------------------------------
# Main loop
#---------------------------------------------------------------------------
TOTAL=0 AFFECTED=0 PATCHED=0 UNKNOWN=0

say ""
say "${C_BOLD}JDK audit for CVE-2026-91403 (compromised eMudhra intermediates)${C_RESET}"
say "Machine: $(hostname)   User: $(id -un)"
say ""

while IFS= read -r home; do
  [ -n "$home" ] || continue
  TOTAL=$((TOTAL + 1))

  allver=$("$home/bin/java" -version 2>&1)
  raw=$(printf '%s' "$allver" | head -1)
  ver=$(printf '%s' "$allver" | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -1)
  [ -n "$ver" ] || ver="?"
  major=$(major_version "$raw")
  [ -n "$major" ] || major=0
  vendor=$(printf '%s' "$allver" \
    | sed -n 's/.*\(Temurin\|Zulu\|Corretto\|Liberica\|GraalVM\|Semeru\|OpenJ9\|Java(TM)\).*/\1/p' \
    | head -1)
  [ -n "$vendor" ] || vendor="OpenJDK"

  if [ "$MODE" = inventory ]; then
    printf '%s\n' "$ver|$raw|$home" >> "$RESULTS"
    continue
  fi

  note "Testing $ver ($vendor) ..."
  if ! run_check "$home" "$major" "$TMPD/out"; then
    status=UNKNOWN
    detail="could not compile/run test"
  else
    counts=$(grep '^COUNTS ' "$TMPD/out" | tail -1)
    cv=$(printf '%s' "$counts" | sed -n 's/.*vuln=\([0-9]*\).*/\1/p'); cv=${cv:-0}
    co=$(printf '%s' "$counts" | sed -n 's/.*ok=\([0-9]*\).*/\1/p');    co=${co:-0}
    if [ "$cv" -gt 0 ]; then
      status=AFFECTED; detail="$cv of 12 compromised chains trusted"
    elif [ "$co" -gt 0 ]; then
      status=PATCHED; detail="all reachable compromised chains rejected"
    else
      status=UNKNOWN; detail="no test host reachable (network/proxy?)"
    fi
  fi

  case "$status" in
    AFFECTED) AFFECTED=$((AFFECTED + 1)) ;;
    PATCHED)  PATCHED=$((PATCHED + 1)) ;;
    *)        UNKNOWN=$((UNKNOWN + 1)) ;;
  esac

  printf '%s|%s|%s|%s|%s\n' "$status" "$ver" "$vendor" "$home" "$detail" >> "$RESULTS"

  # Optional interim mitigation
  if [ "$MODE" = fix ] && [ "$status" = AFFECTED ]; then
    blocked="$home/lib/security/blocked.certs"
    [ -f "$blocked" ] || blocked="$home/jre/lib/security/blacklisted.certs"
    if [ -f "$blocked" ] && [ -f "$TMPD/impacted.json" ]; then
      cp "$blocked" "$blocked.bak.$(date +%Y%m%d%H%M%S)"
      python3 -c "import json;[print(x['sha256']) for x in json.load(open('$TMPD/impacted.json'))]" >> "$blocked" \
        && note "  interim blocklist appended to $blocked (backup kept)"
    fi
  fi
done < "$CANDIDATES"

#---------------------------------------------------------------------------
# Report
#---------------------------------------------------------------------------
if [ "$MODE" = json ]; then
  printf '{"host":"%s","user":"%s","total":%d,"affected":%d,"patched":%d,"unknown":%d,"jdks":[' \
    "$(hostname)" "$(id -un)" "$TOTAL" "$AFFECTED" "$PATCHED" "$UNKNOWN"
  first=1
  while IFS='|' read -r status ver vendor home detail; do
    [ "$first" = 1 ] || printf ','
    first=0
    printf '{"status":"%s","version":"%s","vendor":"%s","home":"%s","detail":"%s"}' \
      "$status" "$ver" "$vendor" "$home" "$detail"
  done < "$RESULTS"
  printf ']}\n'
  [ "$AFFECTED" -eq 0 ] && exit 0 || exit 1
fi

if [ "$MODE" = inventory ]; then
  say "${C_BOLD}Discovered JDKs${C_RESET}"
  say ""
  while IFS='|' read -r ver raw home; do
    printf '  %-10s %s\n             %s\n' "$ver" "$raw" "$home"
  done < "$RESULTS"
  say ""
  say "Total: $TOTAL"
  exit 0
fi

say ""
say "${C_BOLD}Results${C_RESET}"
say ""
while IFS='|' read -r status ver vendor home detail; do
  case "$status" in
    AFFECTED) col=$C_RED ;;
    PATCHED)  col=$C_GREEN ;;
    *)        col=$C_YELLOW ;;
  esac
  printf '  %s%-10s%s  %-9s (%-10s) %s\n' "$col" "$status" "$C_RESET" "$ver" "$vendor" "$detail"
  printf '             %s\n' "$home"
done < "$RESULTS"
say ""
say "  ${C_BOLD}Total:${C_RESET} $TOTAL   ${C_RED}Affected: $AFFECTED${C_RESET}   ${C_GREEN}Patched: $PATCHED${C_RESET}   ${C_YELLOW}Unknown: $UNKNOWN${C_RESET}"
say ""

if [ "$AFFECTED" -gt 0 ]; then
  say "  ${C_RED}Action required.${C_RESET} Update each AFFECTED JDK to a fixed build:"
  say "    27.0.1.0.2 / 25.0.5.0.2 / 21.0.13.0.2 / 17.0.21.0.2 / 11.0.33.0.2 / 8u511"
  say "  The fix keeps the roots and blocks the intermediates via blocked.certs,"
  say "  so upgrading is preferred over deleting roots from cacerts."
  say ""
  exit 1
fi

if [ "$UNKNOWN" -gt 0 ] && [ "$PATCHED" -eq 0 ]; then
  say "  ${C_YELLOW}Inconclusive.${C_RESET} No test host was reachable — rerun on a network"
  say "  that permits outbound HTTPS to *.we-have-a-problem.com."
  say ""
  exit 3
fi

say "  ${C_GREEN}No affected JDK found.${C_RESET}"
say ""
exit 0
