# php2shell-scanner

Forked from [CyberRoute/php2shell-scanner](https://github.com/CyberRoute/php2shell-scanner).

Non-destructive detector for **CVE-2026-109618** and **CVE-2026-109619**
(PHP2Shell) — critical PHP-core remote code execution issues disclosed by the
PHP project on **21 October 2026** (CVSS v4.0 **9.2** each).

This scanner **does not** trigger out-of-memory, plant `<?php` payloads, or
prove remote code execution. Proving RCE for these bugs requires
memory-corruption traffic; that is intentionally out of scope.

## What changed in this fork

Relative to upstream CyberRoute:

- **Aligned detection with the real bugs.** Upstream framed the issue as a
  classic `session.upload_progress` filename-injection + LFI chain. The PHP
  advisories describe memory bugs (OOM corruption and stale global state). Checks
  and wording were rewritten accordingly.
- **Fixed the fixation check.** Upstream treated `session.use_only_cookies=Off`
  as required. On unpatched PHP, the rfc1867 upload-progress path can still take
  `PHPSESSID` from the multipart body when cookies-only is On.
- **Honest verdicts.** No more “VULNERABLE (confirmed)” from an LFI canary alone.
  Canary read-back only proves session-file write, not UAF/OOM RCE.
- **Mitigations from the PHP security team** (per-CVE partial advice; patch is
  the only complete fix) — see [Mitigation](#mitigation).
- **Safer multipart handling:** reject quote/CRLF in probe fields, cap response
  size, require a `FUZZ` marker in `--lfi`, drop “swap canary for PHP tags”
  guidance.
- **Docs/CVE mapping** updated from
  [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
  [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp),
  and the [PHP Foundation post](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/).

## Background (PHP project, 21 Oct 2026)

The PHP project shipped emergency releases **8.5.12**, **8.4.27**, **8.3.36**,
and **8.2.35** after a coordinated disclosure that was disrupted by early CVE
ID leaks (wrong CVSS 10.0 circulated; real score is **9.2**). Both flaws sit in
memory management and error handling that nearly every request touches.

| CVE | Advisory | Summary (PHP security team) |
|-----|----------|------------------------------|
| **CVE-2026-109618** | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | **RCE via OOM corruption.** `longjmp()` on out-of-memory can leave partially initialized request state; shutdown then treats it as valid. Confirmed unauthenticated RCE on **Apache mod_php** with default limits; FPM/FrankenPHP/LSAPI noted as susceptible with caveats. |
| **CVE-2026-109619** | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | **RCE via stale global state.** Worker-retained globals can point at freed request memory; a later request on the **same worker** can use them. Confirmed paths include **PHP 8.5 `fatal_error_backtraces`** and **session upload progress** (producer and/or consumer). |

**Affected:** PHP before the fixed releases above (EOL 8.1 / 8.0 / 7.x / 5.x
have no official fixed packages; vendors may ship backports).

**Impact:** Unauthenticated RCE as the web worker account. Producer and consumer
requests for 109619 must hit the same worker; more workers reduce success rate
but do not remove the bug.

## What it checks

| # | Check | Signal |
|---|--------|--------|
| 1 | Fingerprint | PHP version vs the shared fixed-release table (**both CVEs**) |
| 2 | upload_progress probe | Multipart `PHP_SESSION_UPLOAD_PROGRESS` gets an HTTP response (weak surface signal; relevant to confirmed **109619** session lifecycle) |
| 3 | Body `PHPSESSID` | SID in the multipart body on the rfc1867 path |
| 4 | Session inject (opt-in) | Inert canary in the upload **filename** written into a session file and read back via `--lfi` |

Check 4 proves attacker-controlled bytes can land in a session file via
upload_progress. That is a **surface/precondition** signal — **not** proof of
UAF/OOM RCE.

## Usage

```bash
# Version + surface probes
python3 scan.py --target http://host:port --session-path /index.php --yes

# Also confirm inert canary landed in a session file (needs a file-read/LFI)
python3 scan.py \
  --target http://host:port \
  --session-path /index.php \
  --lfi 'http://host:port/vuln.php?page=FUZZ' \
  --save-path /var/lib/php/sessions \
  --yes
```

- `--session-path` — any path that reaches PHP (upload_progress runs before the script; no `session_start()` required per the advisory).
- `--lfi` — file-read endpoint with a `FUZZ` marker; enables check 4.
- `--save-path` — target `session.save_path` (common defaults are tried if omitted).
- `--yes` — required authorization acknowledgement.

Stdlib only. Multipart probes are plain HTTP (no TLS wrapper yet).

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `AFFECTED + SESSION WRITE CONFIRMED` | Version in advisory range **and** inert canary read from a session file — attack surface live; **RCE not proven** |
| `AFFECTED VERSION + SURFACE PRESENT` | Unpatched version + multipart upload_progress probe got an HTTP response |
| `AFFECTED VERSION` | Banner/version in range for both CVEs; surface unclear |
| `LIKELY PATCHED` | Version ≥ fixed release for its branch (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) |
| `PRECONDITIONS / SURFACE ONLY` | upload_progress-related signals without a clear affected version |
| `NOT DETECTED` | No clear version or surface signals |

Exit `0` if the version is in the affected range or session write was confirmed;
`1` otherwise; `2` if refused / unreachable.

## Mitigation

Guidance below follows the PHP security team advisories. **Updating is the only
complete mitigation for both CVEs.**

### 1. Patch (required)

Upgrade to **8.2.35**, **8.3.36**, **8.4.27**, or **8.5.12** (or later in that
branch), then **restart every PHP worker** (FPM pool, Apache, containers, etc.).
Check your distro/vendor packages — they may backport the fix under a different
version string.

### 2. Partial mitigations if you cannot update yet

These **reduce exposure**; they are **not** a substitute for the patch.

**CVE-2026-109618 (OOM corruption)** — from [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w):

- Set and **enforce** `memory_limit=-1` administratively (pool / `php.ini` /
  server config). Restart every worker. Confirm no pool, directory, or app
  setting restores a finite PHP memory limit.
- Keep `post_max_size` conservative; enforce decoded request size at the
  frontend. Reduce nesting / input / multipart part and header bounds.
- If the app does not need multipart uploads, block `multipart/form-data` before
  it reaches PHP.
- Container/`cgroup` memory limits are incomplete alternatives.
- **Do not** use `RLIMIT_AS` or `RLIMIT_DATA` — they can force `mmap()` failure
  and hit the vulnerable `longjmp()` path.

**CVE-2026-109619 (stale global state)** — from [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp):

- Set `session.upload_progress.enabled=0` in **admin** config (php.ini, FPM
  pool, or server config applied **before** request parsing — **not**
  `ini_set()` / `.user.ini`), then restart every worker. Closes the confirmed
  session upload-progress producer/consumer; does **not** cover every state
  family.
- On **PHP 8.5**, also set `fatal_error_backtraces=0` administratively and
  restart workers (removes the strongest confirmed backtrace producer).
- Optionally `pm.max_requests=1` to break same-worker reuse (performance cost).
- Prefer startup INI over per-request `PHP_VALUE` / `.htaccess` overrides that
  can emit early diagnostics (INI diagnostic consumer path).
- Even after patching, PHP notes it may be prudent to leave
  `session.upload_progress.enabled=0` if you do not need the feature.

Upstream’s `session.use_only_cookies=On` alone is **not** a reliable mitigation
for these CVEs.

### 3. After updating

Still restart all workers so no process keeps the old binary. Re-check
`php -v` / FPM / container images (CLI and web SAPIs can differ).

## Official references

- [PHP Foundation — security release post (21 Oct 2026)](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/)
- [GHSA-w8hw-w9fx-j79w — CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp — CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- Upstream scanner: [CyberRoute/php2shell-scanner](https://github.com/CyberRoute/php2shell-scanner)

## Disclaimer

Authorized security testing and education only. Do not scan systems you do not
own or lack explicit written permission to test.
