#!/usr/bin/env python3
"""
php2shell-scanner — non-destructive detector for CVE-2026-109618 / CVE-2026-109619.

These are PHP-core memory bugs (OOM corruption and stale global state), not the
classic LFI+webshell chain. This tool never triggers OOM, never plants PHP
payloads, and never executes code on the target.

What it can safely establish:
  1. Fingerprint — PHP version vs the fixed releases for both CVEs.
  2. Multipart surface — a PHP_SESSION_UPLOAD_PROGRESS probe is accepted
     (shared entry point especially relevant to CVE-2026-109619).
  3. Session-ID via body — POST-body PHPSESSID on the upload-progress path
     (rfc1867 accepts it even when session.use_only_cookies=On).
  4. Confirm (optional, needs --lfi) — inert canary in the upload filename is
     written into a session file and read back. That proves attacker-controlled
     bytes land in session storage via upload_progress (a precondition used in
     some public write-ups). It does NOT prove UAF/OOM RCE.

It cannot safely prove remote code execution for either CVE; that requires
memory-corruption traffic this scanner deliberately does not send.

Usage:
  python3 scan.py --target http://host:port --yes
  python3 scan.py --target http://host:port --session-path /index.php \\
      --lfi 'http://host:port/vuln.php?page=FUZZ' --save-path /tmp \\
      --yes

AUTHORIZED TESTING ONLY. See README.md.
"""
import argparse
import re
import secrets
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

# Fixed releases from the PHP advisories (both CVEs share this table).
BRANCH_FIX = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}
# EOL branches: no upstream fixed release; treat as affected when PHP is present.
EOL_AFFECTED = {(8, 1), (8, 0), (7, 4), (7, 3), (7, 2), (7, 1), (7, 0),
                (5, 6), (5, 5), (5, 4)}

# php_session_valid_key(): [A-Za-z0-9,-]
_SID_OK = re.compile(r"^[A-Za-z0-9,-]+$")

RESET = "\033[0m"


def c(txt, col):
    cols = {"red": 31, "green": 32, "yellow": 33, "blue": 34, "grey": 90}
    return f"\033[{cols[col]}m{txt}{RESET}" if sys.stdout.isatty() else txt


def classify_version(ver):
    """Return (verdict, note) for a dotted PHP version string."""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", ver or "")
    if not m:
        return "unknown", "could not parse version"
    major, minor, patch = int(m[1]), int(m[2]), int(m[3])
    branch = (major, minor)
    if branch in BRANCH_FIX:
        fix = BRANCH_FIX[branch]
        if patch < fix:
            return "affected", f"{ver} < {major}.{minor}.{fix} (both CVEs)"
        return "patched", f"{ver} >= {major}.{minor}.{fix}"
    if branch in EOL_AFFECTED:
        return "affected", f"{major}.{minor}.x is EOL; no official fixed release"
    if major > 8 or (major == 8 and minor > 5):
        return "unknown", f"{ver} is newer than the advisory range"
    return "unknown", f"{ver} not in the advisory table"


def fingerprint(target, timeout):
    """GET the target root; return (status, headers dict, body bytes)."""
    req = urllib.request.Request(
        target, method="GET",
        headers={"User-Agent": "php2shell-scanner/1.1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(65536)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(65536)
    except Exception as e:
        return None, {"_error": str(e)}, b""


def upload_progress_post(host, port, path, sid, filename, timeout,
                         progress_name="x"):
    """Send one upload_progress multipart POST over a raw HTTP/1.1 socket.

    PHPSESSID is only in the POST body (rfc1867 path). No Cookie header.
    Filename and progress_name must stay free of quotes/CRLF.
    Returns (status_line, body_bytes, set_cookie_header).
    """
    if not _SID_OK.match(sid):
        raise ValueError("session id has invalid characters for PHP")
    for label, val in (("filename", filename), ("progress_name", progress_name)):
        if any(ch in val for ch in '"\r\n'):
            raise ValueError(f"{label} contains forbidden characters")

    boundary = "SCAN" + secrets.token_hex(4)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
        f"\r\n\r\n{progress_name}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"'
        f"\r\n\r\nZ\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: php2shell-scanner/1.1\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    )

    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(headers.encode("ascii") + body)
        s.settimeout(timeout)
        resp = b""
        while True:
            try:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 2_000_000:
                    break
            except socket.timeout:
                break

    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"
    head = resp.split(b"\r\n\r\n", 1)[0] if b"\r\n\r\n" in resp else resp
    body_out = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
    m = re.search(rb"set-cookie:\s*(.*)", head, re.I)
    set_cookie = m.group(1).decode("latin1", "replace").strip() if m else ""
    return status, body_out, set_cookie


def lfi_read(lfi_template, file_path, timeout):
    """GET the LFI endpoint with FUZZ replaced by file_path; return body bytes."""
    if "FUZZ" not in lfi_template:
        raise ValueError("--lfi template must contain the FUZZ marker")
    url = lfi_template.replace("FUZZ", urllib.parse.quote(file_path, safe="/"))
    req = urllib.request.Request(
        url, headers={"User-Agent": "php2shell-scanner/1.1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(262144)
    except urllib.error.HTTPError as e:
        return e.read(262144)
    except Exception:
        return b""


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="http://host:port (plain HTTP)")
    ap.add_argument("--session-path", default="/",
                    help="path that reaches PHP (default '/'); upload_progress "
                         "runs before the script")
    ap.add_argument("--lfi", default=None,
                    help="optional LFI/file-read URL with FUZZ marker to confirm "
                         "inert canary landed in a session file")
    ap.add_argument("--save-path", default=None,
                    help="session.save_path on the target; if omitted, common "
                         "candidates are tried for canary read-back")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--yes", action="store_true",
                    help="confirm you are authorized to test this target")
    args = ap.parse_args()

    if not args.yes:
        print(c("Refusing to run without --yes (authorized-testing acknowledgement).",
                "yellow"))
        print("Only scan systems you own or have explicit written permission to test.")
        sys.exit(2)

    u = urlparse(args.target)
    if u.scheme not in ("http", "https") or not u.hostname:
        print(c("[!] --target must be http://host[:port] or https://...", "red"))
        sys.exit(2)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    if u.scheme == "https":
        print(c("[!] Multipart probes use raw HTTP sockets; HTTPS/TLS is not "
                "supported. Fingerprint GET may still work via urllib.", "yellow"))

    path = args.session_path if args.session_path.startswith("/") else "/" + args.session_path

    print(c("php2shell-scanner — CVE-2026-109618 / CVE-2026-109619", "blue"))
    print(f"[*] Target: {args.target}")
    print(c("    Non-destructive: no OOM, no PHP payload, no code execution.\n", "grey"))

    results = {}

    # --- 1. Version fingerprint (both CVEs) ---------------------------------
    status, headers, body = fingerprint(args.target, args.timeout)
    if status is None:
        print(c(f"[1] Fingerprint       FAIL — unreachable ({headers.get('_error')})",
                "red"))
        sys.exit(2)
    banner = headers.get("x-powered-by", "") or headers.get("server", "")
    text = body.decode("latin1", "replace")
    vm = re.search(r"PHP/([\d.]+)", banner) or re.search(r"PHP[/ ]([\d.]+)", text)
    version = vm.group(1) if vm else None
    verdict, note = classify_version(version)
    results["version"] = verdict
    label = {
        "affected": c("AFFECTED", "red"),
        "patched": c("patched", "green"),
        "unknown": c("unknown", "yellow"),
    }[verdict]
    print(f"[1] Fingerprint       PHP {version or '?'}  -> {label}")
    print(c(f"       {note}  (banner: {banner or 'none'})", "grey"))
    print(c("       applies to both CVE-2026-109618 and CVE-2026-109619", "grey"))

    # --- 2. upload_progress multipart surface -------------------------------
    # Relevant especially to CVE-2026-109619; many public paths also use it.
    # A non-error HTTP response only means the request reached PHP/HTTP stack —
    # not that upload_progress is enabled. Treat as weak surface signal.
    sid_up = "scanup" + secrets.token_hex(10)
    try:
        st_up, _, _ = upload_progress_post(
            host, port, path, sid_up, "probe.txt", args.timeout)
    except (OSError, ValueError) as e:
        st_up = f"ERR {e}"
    up_ok = bool(re.match(r"HTTP/\d", st_up)) and not st_up.startswith("ERR")
    results["upload_progress_probe"] = up_ok
    print(f"[2] upload_progress   {'OK  ' if up_ok else 'no  '}"
          f"multipart PHP_SESSION_UPLOAD_PROGRESS probe -> {st_up}")
    if up_ok:
        print(c("       weak signal: response received; does not prove the "
                "INI flag is On", "grey"))

    # --- 3. Body PHPSESSID on rfc1867 path ----------------------------------
    # Not the same as use_only_cookies=Off. Upload-progress historically took
    # PHPSESSID from the multipart body even when cookies-only was set.
    sid_fix = "scanfix" + secrets.token_hex(10)
    try:
        st_fx, _, setck = upload_progress_post(
            host, port, path, sid_fix, "canary.txt", args.timeout)
    except (OSError, ValueError) as e:
        print(c(f"[3] Body PHPSESSID    FAIL — {e}", "red"))
        st_fx, setck = "", ""
    http_ok = bool(re.match(r"HTTP/\d", st_fx))
    # If the server echoes a different PHPSESSID cookie, body SID may have been
    # ignored for cookie issuance — still inconclusive for rfc1867 session file.
    issued_other = bool(re.search(r"PHPSESSID=", setck, re.I)) and sid_fix not in setck
    results["body_sid_probe"] = http_ok
    print(f"[3] Body PHPSESSID    {'OK  ' if http_ok else 'no  '}"
          f"POST-body SID on upload-progress path "
          f"{'(server issued different cookie)' if issued_other else ''}")
    if setck:
        print(c(f"       Set-Cookie: {setck}", "grey"))
    print(c("       note: use_only_cookies=On does not block this rfc1867 path "
            "on unpatched PHP", "grey"))

    # --- 4. Inert canary in session file (optional) -------------------------
    confirmed = False
    if args.lfi:
        canary = "P2S_" + secrets.token_hex(12)  # no PHP tags, no serialized junk
        sid_can = "scancan" + secrets.token_hex(10)
        try:
            upload_progress_post(
                host, port, path, sid_can, canary, args.timeout)
            candidates = ([args.save_path] if args.save_path else
                          ["/var/lib/php/sessions", "/var/lib/php/session",
                           "/var/lib/php5", "/tmp", "/tmp/sessions"])
            hit_path = None
            for base in candidates:
                sess = f"{base.rstrip('/')}/sess_{sid_can}"
                data = lfi_read(args.lfi, sess, args.timeout)
                if canary.encode("ascii") in data:
                    hit_path = base
                    break
            confirmed = hit_path is not None
            results["session_inject"] = confirmed
            if confirmed:
                print(c(f"[4] Session inject    CONFIRMED — canary in "
                        f"{hit_path}/sess_{sid_can}", "red"))
                print(c("       proves upload_progress wrote attacker-controlled "
                        "filename bytes into a session file", "grey"))
                print(c("       does NOT prove CVE RCE (no OOM/UAF attempted)",
                        "grey"))
                print(c(f"       canary={canary}", "grey"))
            else:
                print(f"[4] Session inject    no  — canary not read back "
                      f"(wrong --save-path, no LFI, or upload_progress Off)")
        except (OSError, ValueError) as e:
            print(c(f"[4] Session inject    FAIL — {e}", "red"))
    else:
        print(c("[4] Session inject    skipped — pass --lfi to confirm session "
                "file write", "grey"))

    # --- Verdict ------------------------------------------------------------
    print()
    print(c("CVE mapping:", "blue"))
    print(c("  CVE-2026-109618  OOM / incomplete-state corruption during request "
            "init (multipart often used).", "grey"))
    print(c("  CVE-2026-109619  Stale global state across requests; upload_progress "
            "is a confirmed trigger path.", "grey"))
    print()

    if results.get("version") == "patched":
        v = c("LIKELY PATCHED", "green")
        detail = ("PHP version is at or above the fixed release for its branch "
                  "(both CVEs).")
    elif confirmed and results.get("version") == "affected":
        v = c("AFFECTED + SESSION WRITE CONFIRMED", "red")
        detail = ("unpatched version and upload_progress session write proven; "
                  "high confidence the shared attack surface is live. RCE not proven.")
    elif results.get("version") == "affected" and results.get("upload_progress_probe"):
        v = c("AFFECTED VERSION + SURFACE PRESENT", "red")
        detail = ("banner/version in range and multipart upload_progress probe "
                  "got an HTTP response. Supply --lfi to confirm session write.")
    elif results.get("version") == "affected":
        v = c("AFFECTED VERSION", "red")
        detail = ("PHP version is in the advisory range for both CVEs; "
                  "multipart surface unclear.")
    elif results.get("upload_progress_probe") or confirmed:
        v = c("PRECONDITIONS / SURFACE ONLY", "yellow")
        detail = ("version unknown or patched, but upload_progress-related "
                  "signals were observed.")
    else:
        v = c("NOT DETECTED", "green")
        detail = "no clear version or upload_progress signals over HTTP."

    print(f"[=] Verdict: {v}")
    print(c(f"    {detail}", "grey"))
    print(c("    Mitigate: upgrade to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+; "
            "partial: session.upload_progress.enabled=Off (restart workers).",
            "grey"))
    print(c("    This tool does not exploit either CVE.", "grey"))

    # Exit 0 only when version is clearly in the affected range (actionable).
    sys.exit(0 if results.get("version") == "affected" or confirmed else 1)


if __name__ == "__main__":
    main()
