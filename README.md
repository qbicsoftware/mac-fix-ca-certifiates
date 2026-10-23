# macOS / conda fix for the eMudhra CA compromise

> [!IMPORTANT]
> ## ⬇️ Install and run
>
> **Copy this one line into your terminal and press Enter:**
>
> ```bash
> curl -fsSL https://raw.githubusercontent.com/qbicsoftware/mac-fix-ca-certifiates/main/install.sh | bash && ./fix-certificates.sh assess
> ```
>
> That downloads `fix-certificates.sh` into the directory you are in, makes it
> executable and runs the read-only assessment. Nothing is changed by it.
>
> **Then apply the fixes:**
>
> ```bash
> ./fix-certificates.sh apply
> ```

**Prefer to read the code before running it?**

```bash
curl -fsSLO https://raw.githubusercontent.com/qbicsoftware/mac-fix-ca-certifiates/main/install.sh
less install.sh          # read it
bash install.sh          # then run it
```

The installer only needs `curl` or `wget`. It downloads to a temporary file,
refuses to install anything that is not a shell script or fails a syntax
check, and prints the SHA-256 of what it wrote. Pass a directory as the first
argument to install somewhere else, e.g. `./install.sh ~/Downloads`.

---

## The problem

Private keys for **eight eMudhra intermediate CA certificates** were left with
effectively no entropy and can be recovered from the public certificates in
under a second. Anyone holding those keys can impersonate any website or
service to clients that still trust the affected chains.

* Incident write-up: <https://emudhra.we-have-a-problem.com/>
* heise: <https://www.heise.de/en/news/eMudhra-incident-compromises-eight-CA-certificates-11494689.html>
* Cisco Talos: <https://blog.talosintelligence.com/compromised-intermediate-certificates/>

Apple blocked the compromised intermediates in the **macOS keychain** (so
Safari and most GUI apps are fine), but the *command line tooling* is not
covered:

| Client | Trust store | Status on an unpatched Mac |
| --- | --- | --- |
| `/usr/bin/curl`, `git`, `perl`, `ruby`, `openssl`, built-in `python3` | `/etc/ssl/cert.pem` | **trusts the compromised chains** |
| `pip` and virtualenvs | bundled `certifi` / `PIP_CERT` | **trusts the compromised chains** |
| every conda environment | per-env `certifi` + `ssl/cacert.pem` | **trusts the compromised chains** |

`fix-certificates.sh` assesses all of those and then fixes them.

## Usage

```bash
./fix-certificates.sh              # assess only (default, read-only)
./fix-certificates.sh assess       # same thing
./fix-certificates.sh apply        # apply the fixes
./fix-certificates.sh apply --dry-run   # show what would change, change nothing
```

Useful flags:

| Flag | Meaning |
| --- | --- |
| `-n`, `--dry-run` | `apply`: only report what would be done |
| `-y`, `--yes` | never prompt for confirmation |
| `--offline` | skip the live TLS probes (offline / air-gapped hosts) |
| `--json` | print a machine readable report on stdout (human output goes to stderr) |
| `--no-conda` | skip the conda environment sweep |
| `--no-pip` | skip the pip / python remediation |
| `--no-system` | skip `/etc/ssl/cert.pem` |
| `--timeout N` | network timeout in seconds (default 15) |

Exit code is `0` when nothing is left to fix and `1` when something is still
affected, so it can be used in scripts and CI:

```bash
./fix-certificates.sh assess --json --offline | jq '.summary'
```

## What the assessment does

The report is deliberately terse: one line per trust store. While a check is
running the line shows what is being investigated and is then replaced by the
result, so on a terminal you see `… checking conda env: base` and then
`[FAIL] conda env: base — 2 of 2 CA bundle(s) affected`. In a piped log the
progress lines are dropped and only the results remain.

```
1. macOS system trust store
  used by curl, git, perl, ruby, openssl and the built-in python3
  [FAIL] /etc/ssl/cert.pem — trusts AAA Certificate Services, emSign ECC Root CA - G3; live probe ACCEPTED a forged certificate
  [ ok ] macOS keychain — Apple already blocks the certificates

2. Homebrew trust stores
  [ ok ] /opt/homebrew/etc/ca-certificates/cert.pem
  [ ok ] /opt/homebrew/etc/openssl@3/cert.pem

3. Python interpreters and pip
  [ ok ] certifi of /usr/bin/python3
  [ warn ] pip uses its own bundled certifi (no pip.conf, PIP_CERT unset)

4. conda environments
  conda: /usr/local/miniconda3/bin/conda  (conda 23.11.0)
  [FAIL] conda env: base — 2 of 2 CA bundle(s) affected
      installed: certifi-2023.11.17-py311hecd8cb5_0, ca-certificates-2023.08.22-hecd8cb5_0
      /usr/local/miniconda3/lib/python3.11/site-packages/certifi/cacert.pem
        trusts AAA Certificate Services, emSign ECC Root CA - G3; live probe ACCEPTED a forged certificate
      /usr/local/miniconda3/ssl/cacert.pem
        trusts AAA Certificate Services, emSign ECC Root CA - G3; live probe ACCEPTED a forged certificate
  [ warn ] conda env: codeandfun — no CA bundle found
```

Everything that is still affected is repeated in a loud, grouped block at the
end so it cannot be missed:

```
Summary
  affected : 16
  clean    : 5
  warnings : 1
  skipped  : 7

  !! ATTENTION !! 16 trust store(s) still trust the compromised CA
  --------------------------------------------------------------------

    macOS system trust store
      • /etc/ssl/cert.pem
        trusts AAA Certificate Services, emSign ECC Root CA - G3; live probe ACCEPTED a forged certificate

    conda env: base
      • /usr/local/miniconda3/lib/python3.11/site-packages/certifi/cacert.pem
        trusts AAA Certificate Services, emSign ECC Root CA - G3; live probe ACCEPTED a forged certificate
```

### Coverage

1. **macOS system trust store** — `/etc/ssl/cert.pem` plus a live keychain
   check via `security verify-cert`.
2. **Homebrew trust stores** — `ca-certificates`, `openssl@3`, `openssl`.
3. **Python interpreters on the host** — every `python3` found, its `certifi`
   bundle, and the pip configuration.
4. **All conda environments** — enumerated with `conda env list --json`, not
   just `base`. For every environment it checks each `certifi` bundle and the
   OpenSSL bundle (`ssl/cacert.pem`), reports the installed `certifi` /
   `ca-certificates` versions, and probes whether that environment's Python
   still accepts a forged certificate.

Detection is done by **SHA-256 fingerprint**, not by matching subject names.
That matters: the compromised roots are

* `AAA Certificate Services` (Comodo / Sectigo) — `D7A7A0FB…9EF4`
* `emSign ECC Root CA - G3` (eMudhra) — `86A1ECBA…BE6B`

while the other Comodo and eMudhra roots (`emSign Root CA - G1`,
`emSign ECC Root CA - C3`, `emSign Root CA - C1`, `COMODO CA`, …) are
**not** affected and must be kept. A naive `awk` regex over certificate
subjects throws away the wrong ones and leaves dangling section headers behind.

Each affected bundle is also probed over the network: if the client accepts a
certificate that chains to a compromised intermediate, the assessment says so
explicitly. This catches clients that ignore revocation and Certificate
Transparency as well.

## What `apply` changes

Every file it touches is backed up first (`<file>.bak.<timestamp>`), and it
refuses to write a bundle if the result looks wrong.

1. **`/etc/ssl/cert.pem`** — removes exactly the two compromised roots and
   their descriptive blocks, keeping the file's `### ` / `=== ` structure
   intact and every other certificate in place. Needs `sudo`.
2. **pip / python** — writes `~/.config/pip/pip.conf` with
   `cert = /etc/ssl/cert.pem` (user level, PEP 668 safe) and sets `PIP_CERT`
   for the interpreter's stdlib, matching the upstream advice.
3. **conda environments** — runs
   `conda install -p <env> -c <channel> certifi ca-certificates` for every
   environment. If conda cannot reach a channel (offline host, no patched
   package yet), it falls back to patching the affected bundle in place so the
   environment is protected either way.
4. **Re-verification** — the whole assessment runs again and the exit code
   reflects the final state.

## After running

Open a new shell (and re-activate any conda environments) so running processes
pick up the new bundles. Browsers and GUI apps use the keychain, which Apple
already patched — keep macOS up to date rather than relying on this script for
those.

This script only covers the trust stores listed above. Anything that ships its
own embedded root store (Docker Desktop, VS Code, Electron apps, language
runtimes, VPN clients, …) still needs its own update.
