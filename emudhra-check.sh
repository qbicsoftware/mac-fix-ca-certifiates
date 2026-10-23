#!/bin/bash
#
# emudhra-check.sh - Audit a macOS machine's JDKs against CVE-2026-91403
#                   (compromised eMudhra intermediate CAs).
#
# Discovers every JDK it can find (system installers, SDKMAN, Homebrew, jenv,
# asdf, mise) and tests whether each one still accepts TLS chains signed by the
# compromised intermediates. For every affected JDK it also reports where that
# JDK was installed from and the command that updates it.
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

# --- Homebrew cask awareness ---------------------------------------------------
# oracle-jdk@21, microsoft-openjdk, temurin, zulu, corretto … install into
# /Library/Java/JavaVirtualMachines as a .pkg, so the path alone cannot tell
# them apart from a manual .pkg install. Ask Homebrew.
BREW_CASKS=""
BREW_CASKS_READY=0
brew_casks() {
  [ "$BREW_CASKS_READY" = 1 ] || {
    BREW_CASKS_READY=1
    if command -v brew >/dev/null 2>&1; then
      BREW_CASKS="$(brew list --cask 2>/dev/null)"
    fi
  }
  printf '%s\n' "$BREW_CASKS"
}

bundle_name() {
  # /Library/.../jdk-21.jdk/Contents/Home -> jdk-21.jdk
  basename "$(printf '%s' "$1" | sed 's|/Contents/Home$||')"
}

cask_from_bundle() {
  # Map an installed bundle directory to its Homebrew cask token.
  case "$1" in
    jdk-21*|jdk-21.jdk) printf 'oracle-jdk@21\n' ;;
    jdk-17*|jdk-17.jdk) printf 'oracle-jdk@17\n' ;;
    jdk-*)              printf 'oracle-jdk\n' ;;
    ms-*)               printf 'microsoft-openjdk\n' ;;
    temurin-*)          printf 'temurin\n' ;;
    zulu-*)             printf 'zulu\n' ;;
    corretto-*)         printf 'corretto\n' ;;
    liberica-*)         printf 'liberica-jdk\n' ;;
    *)                  printf '\n' ;;
  esac
}

vendor_of() {
  # Vendor from the whole `java -version` output.
  case "$1" in
    *Temurin*|*"Eclipse Adoptium"*) printf 'Eclipse Temurin\n' ;;
    *Zulu*)                         printf 'Azul Zulu\n' ;;
    *Corretto*)                     printf 'Amazon Corretto\n' ;;
    *Liberica*)                     printf 'BellSoft Liberica\n' ;;
    *GraalVM*)                      printf 'GraalVM\n' ;;
    *Microsoft*)                    printf 'Microsoft Build of OpenJDK\n' ;;
    *"Java(TM) SE"*)                printf 'Oracle JDK\n' ;;
    *)                              printf 'OpenJDK\n' ;;
  esac
}

vendor_url() {
  case "$1" in
    *Oracle*)    printf 'https://www.oracle.com/java/technologies/downloads/' ;;
    *Microsoft*) printf 'https://aka.ms/download-jdk' ;;
    *Zulu*)      printf 'https://www.azul.com/downloads/' ;;
    *Corretto*)  printf 'https://aws.amazon.com/corretto/' ;;
    *Liberica*)  printf 'https://bell-sw.com/pages/downloads/' ;;
    *)           printf 'https://adoptium.net/temurin/releases/' ;;
  esac
}

install_source() {  # <home> <vendor-name>
  # Echoes "<source>|<how to update>".
  local home="$1" vendor="$2" bundle cask

  case "$home" in
    "$HOME"/.sdkman/candidates/java/*)
      printf '%s\n' "SDKMAN|sdk install java <fixed-build>-tem && sdk default java <fixed-build>-tem"
      return ;;
  esac

  case "$home" in
    /opt/homebrew/*|/usr/local/*)
      if printf '%s' "$home" | grep -q '/Cellar/'; then
        printf '%s\n' "Homebrew|brew upgrade <formula>"
      else
        printf '%s\n' "Homebrew|brew upgrade <formula>  (or: brew reinstall <formula>)"
      fi
      return ;;
  esac

  # JavaVirtualMachines: a Homebrew cask, a manual .pkg, or a tarball
  case "$home" in
    /Library/Java/*|"$HOME"/Library/Java/*)
      bundle="$(bundle_name "$home")"
      cask="$(cask_from_bundle "$bundle")"
      if [ -n "$cask" ] && brew_casks | grep -qx "$cask"; then
        printf '%s\n' "Homebrew cask|brew upgrade --cask $cask"
        return
      fi
      printf '%s\n' ".pkg ($vendor)|install the $vendor <fixed-build> .pkg ($(vendor_url "$vendor")), then /usr/libexec/java_home -V"
      return ;;
  esac

  case "$home" in
    /opt/*|/usr/share/*)
      printf '%s\n' "manual/tarball|replace the tarball with the fixed build (jdk.java.net / vendor)"
      return ;;
  esac

  printf '%s\n' "unknown|update this JDK to the fixed build for its release family"
}

homebrew_formula() {
  # Best-effort formula name for a Homebrew JDK path.
  case "$1" in
    *openjdk@21*) printf 'openjdk@21\n' ;;
    *openjdk@17*) printf 'openjdk@17\n' ;;
    *openjdk@11*) printf 'openjdk@11\n' ;;
    *openjdk@8*)  printf 'openjdk@8\n' ;;
    *openjdk*)    printf 'openjdk\n' ;;
    *)            printf 'openjdk\n' ;;
  esac
}

fixed_build_for_major() {
  # Fixed eMudhra/CVE-2026-91403 build per release family ("" if EOL family).
  case "$1" in
    27) printf '27.0.1.0.2\n' ;;
    25) printf '25.0.5.0.2\n' ;;
    21) printf '21.0.13.0.2\n' ;;
    17) printf '17.0.21.0.2\n' ;;
    11) printf '11.0.33.0.2\n' ;;
    8)  printf '8u511\n' ;;
    *)  printf '\n' ;;
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
  if curl -fsS -o "$TMPD/impacted.json" \
       "https://emudhra.we-have-a-problem.com/impacted-intermediates.json" 2>/dev/null \
     && [ -s "$TMPD/impacted.json" ]; then
    note "  $(python3 -c "import json;print(len(json.load(open('$TMPD/impacted.json'))))" 2>/dev/null) fingerprints"
  else
    note "  could not fetch list; --fix will have nothing to apply"
    rm -f "$TMPD/impacted.json"
  fi
fi

# Markup appended to blocked.certs so reruns are idempotent.
MARKER="# eMudhra compromised intermediates (CVE-2026-91403)"

# mitigate_jdk <home>
# Appends the compromised-intermediate fingerprints to that JDK's own
# blocklist. Falls back to sudo for /Library installs. Prints a status line.
mitigate_jdk() {
  local home="$1" blocked="" hashes rc
  for cand in "$home/lib/security/blocked.certs" \
              "$home/jre/lib/security/blacklisted.certs"; do
    [ -f "$cand" ] && blocked="$cand" && break
  done
  if [ -z "$blocked" ]; then
    note "  --fix: no blocklist file under $home (needs a full JDK, not a JRE)"
    return 1
  fi
  if grep -qF "$MARKER" "$blocked" 2>/dev/null; then
    note "  --fix: already mitigated ($blocked)"
    return 0
  fi

  hashes="$(python3 -c "
import json
for x in json.load(open('$TMPD/impacted.json')):
    h = x.get('sha256') or x.get('fingerprint')
    if h: print(h.upper())
" 2>/dev/null)"
  [ -n "$hashes" ] || { note "  --fix: no fingerprints available"; return 1; }

  local sudo=""
  if [ ! -w "$blocked" ]; then
    command -v sudo >/dev/null 2>&1 || { note "  --fix: $blocked not writable and sudo unavailable"; return 1; }
    sudo="sudo"
  fi

  # verified backup first, exactly like the shell/conda script does
  if ! $sudo cp -p "$blocked" "$blocked.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null; then
    note "  --fix: could not back up $blocked - refusing to modify it"
    return 1
  fi

  { printf '\n%s\n' "$MARKER"; printf '%s\n' "$hashes"; } | $sudo tee -a "$blocked" >/dev/null 2>&1
  if grep -qF "$MARKER" "$blocked" 2>/dev/null; then
    note "  --fix: appended fingerprints to $blocked (backup kept)"
    return 0
  fi
  note "  --fix: failed to write $blocked"
  return 1
}

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
  vendor=$(vendor_of "$allver")

  source_line=$(install_source "$home" "$vendor")
  isource=${source_line%%|*}
  iupdate=${source_line#*|}
  # Resolve the concrete fixed build and Homebrew formula so the command shown
  # is copy-pasteable.
  fixed=$(fixed_build_for_major "$major")
  if [ -n "$fixed" ]; then
    iupdate=$(printf '%s' "$iupdate" | sed "s|<fixed-build>|$fixed|g")
  fi
  case "$isource" in
    Homebrew*) iupdate=$(printf '%s' "$iupdate" | sed "s|<formula>|$(homebrew_formula "$home")|") ;;
  esac

  if [ "$MODE" = inventory ]; then
    printf '%s\n' "$ver|$raw|$home|$isource" >> "$RESULTS"
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

  printf '%s|%s|%s|%s|%s|%s|%s\n' "$status" "$ver" "$vendor" "$home" "$detail" "$isource" "$iupdate" >> "$RESULTS"

  # Optional interim mitigation
  if [ "$MODE" = fix ] && [ "$status" = AFFECTED ]; then
    if [ -s "$TMPD/impacted.json" ]; then
      mitigate_jdk "$home"
    else
      note "  --fix: no fingerprint list; mitigation skipped"
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
  while IFS='|' read -r status ver vendor home detail isource iupdate; do
    [ "$first" = 1 ] || printf ','
    first=0
    printf '{"status":"%s","version":"%s","vendor":"%s","source":"%s","home":"%s","detail":"%s"}' \
      "$status" "$ver" "$vendor" "$isource" "$home" "$detail"
  done < "$RESULTS"
  printf ']}\n'
  [ "$AFFECTED" -eq 0 ] && exit 0 || exit 1
fi

if [ "$MODE" = inventory ]; then
  say "${C_BOLD}Discovered JDKs${C_RESET}"
  say ""
  while IFS='|' read -r ver raw home isource; do
    printf '  %-10s %-9s %s\n             %s\n' "$ver" "($isource)" "$raw" "$home"
  done < "$RESULTS"
  say ""
  say "Total: $TOTAL"
  exit 0
fi

say ""
say "${C_BOLD}Results${C_RESET}"
say ""
while IFS='|' read -r status ver vendor home detail isource iupdate; do
  case "$status" in
    AFFECTED) col=$C_RED ;;
    PATCHED)  col=$C_GREEN ;;
    *)        col=$C_YELLOW ;;
  esac
  printf '  %s%-10s%s  %-9s (%s) %s\n' "$col" "$status" "$C_RESET" "$ver" "$vendor" "$detail"
  printf '             %s\n' "$home"
  if [ "$status" = AFFECTED ]; then
    printf '             %ssource: %s -> %s%s\n' "$C_BOLD" "$isource" "$iupdate" "$C_RESET"
  fi
done < "$RESULTS"
say ""
say "  ${C_BOLD}Total:${C_RESET} $TOTAL   ${C_RED}Affected: $AFFECTED${C_RESET}   ${C_GREEN}Patched: $PATCHED${C_RESET}   ${C_YELLOW}Unknown: $UNKNOWN${C_RESET}"
say ""

if [ "$AFFECTED" -gt 0 ]; then
  say "  ${C_RED}Action required.${C_RESET} The per-JDK update command is shown next to each"
  say "  AFFECTED entry above. Fixed builds: 27.0.1.0.2 / 25.0.5.0.2 / 21.0.13.0.2 /"
  say "  17.0.21.0.2 / 11.0.33.0.2 / 8u511."
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
