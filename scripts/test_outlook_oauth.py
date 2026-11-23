#!/usr/bin/env python3
"""
Phase 0 spike: find out which OAuth2 scope Outlook.com's IMAP server accepts.

Runs on a headless machine. Standard library only (no msal needed).

What it does
  1. Signs in with the device-code flow: it prints a short code and a URL; you
     open the URL in a browser on ANY other device (phone, laptop), enter the
     code and sign in with the Outlook.com account.
  2. Uses the refresh token to request an access token for each scope variant
     (so you only sign in once).
  3. For each token, tries IMAP "AUTHENTICATE XOAUTH2" against
     outlook.office365.com:993 and lists the folders.
  4. Prints which variants worked, and the IMAP_OAUTH_SCOPES value to use.

Nothing is changed or deleted on the mailbox: the INBOX is opened read-only and
no messages are fetched. Tokens are never printed.

Prerequisites (Microsoft Entra admin centre, app registration)
  - Supported account types: include personal Microsoft accounts
  - "Allow public client flows": Yes
  - Delegated API permissions: IMAP.AccessAsUser.All, offline_access
  - Copy the Application (client) ID

Usage
  python test_outlook_oauth.py --client-id <id> --email you@outlook.com
  (or set MS_CLIENT_ID and MS_EMAIL)

The refresh token is saved (chmod 600) so reruns skip the sign-in. It is a
credential: run with --forget when finished to delete it.
"""

from __future__ import annotations

import argparse
import base64
import imaplib
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

AUTHORITY_BASE = os.environ.get("MS_AUTHORITY_BASE", "https://login.microsoftonline.com")

SCOPE_VARIANTS = {
    # Named in Microsoft's IMAP OAuth documentation.
    "outlook": "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
    # Microsoft Graph spelling; some personal-account setups issue these instead.
    "graph": "https://graph.microsoft.com/IMAP.AccessAsUser.All offline_access",
    # No resource prefix; Microsoft resolves it itself.
    "bare": "IMAP.AccessAsUser.All offline_access",
}

# (substring of the error text, advice)
HINTS = [
    ("AADSTS7000218", "Turn on 'Allow public client flows' in the app registration (Authentication page)."),
    ("AADSTS70011", "The scope was rejected. Try --login-scope graph or bare, or check the app's API permissions."),
    ("AADSTS65001", "Consent is missing. Check that IMAP.AccessAsUser.All and offline_access are added as delegated permissions."),
    ("AADSTS700016", "The client ID was not found. Check --client-id."),
    ("AADSTS70002", "The app may not be set up for personal Microsoft accounts. Check 'Supported account types'."),
    ("AADSTS500200", "The app is not set up for personal Microsoft accounts. Check 'Supported account types'."),
    ("AADSTS50020", "The signed-in account type isn't allowed by the app. Check 'Supported account types'."),
    ("invalid_grant", "The saved sign-in is no longer valid. Rerun with --forget and sign in again."),
]


CURRENT_STEP = "starting"


def step(message: str) -> None:
    """Print a timestamped progress line and remember it for Ctrl-C reports."""
    global CURRENT_STEP
    CURRENT_STEP = message
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


_ORIGINAL_GETADDRINFO = socket.getaddrinfo


def force_ipv4() -> None:
    """Make every later connection use IPv4 only."""
    socket.getaddrinfo = lambda *a, **k: [
        i for i in _ORIGINAL_GETADDRINFO(*a, **k) if i[0] == socket.AF_INET
    ]


def preflight(label: str, host: str, port: int) -> bool:
    """Show DNS and TCP timing so slow or broken networking is visible.

    Returns True when IPv6 failed but IPv4 worked, i.e. IPv4-only is the fix.
    """
    ipv6_failed = ipv4_ok = False
    started = time.monotonic()
    step(f"Network check: resolving {label} ({host})")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        die(f"Cannot resolve {host}: {exc}. Check the Pi's DNS and internet connection.")
    print(f"    resolved in {time.monotonic() - started:.1f}s", flush=True)
    seen = set()
    for family, _type, _proto, _canon, sockaddr in infos:
        name = "IPv6" if family == socket.AF_INET6 else "IPv4"
        if name in seen:
            continue
        seen.add(name)
        t0 = time.monotonic()
        try:
            with socket.create_connection(sockaddr[:2], timeout=5):
                print(f"    {name} connect OK ({time.monotonic() - t0:.1f}s)", flush=True)
                ipv4_ok = ipv4_ok or name == "IPv4"
        except OSError as exc:
            print(f"    {name} connect FAILED after {time.monotonic() - t0:.1f}s: {exc}", flush=True)
            ipv6_failed = ipv6_failed or name == "IPv6"
    return ipv6_failed and ipv4_ok


def die(message: str, code: int = 2) -> "None":
    print(f"\nERROR: {message}", file=sys.stderr)
    sys.exit(code)


def hint_for(text: str) -> str:
    for marker, advice in HINTS:
        if marker in text:
            return advice
    return ""


# --------------------------------------------------------------------------
# Token endpoint helpers
# --------------------------------------------------------------------------

def post_form(url: str, fields: dict, timeout: float = 30.0) -> dict:
    """POST form data and return the parsed JSON, including error responses."""
    step(f"Contacting {urllib.parse.urlsplit(url).netloc}{urllib.parse.urlsplit(url).path}")
    data = urllib.parse.urlencode(fields).encode("ascii")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"error": f"http_{exc.code}", "error_description": body[:300]}
    except (urllib.error.URLError, OSError) as exc:
        die(f"Could not reach {url}: {exc}")


def describe_error(response: dict) -> str:
    text = f"{response.get('error', 'unknown_error')}: {str(response.get('error_description', '')).strip()}"
    return " ".join(text.split())[:400]


def device_login(authority: str, client_id: str, scope: str) -> dict:
    start = post_form(f"{authority}/oauth2/v2.0/devicecode",
                      {"client_id": client_id, "scope": scope})
    if "device_code" not in start:
        text = describe_error(start)
        die(f"Could not start sign-in: {text}\n  {hint_for(text)}".rstrip())

    url = start.get("verification_uri") or start.get("verification_url") or "https://microsoft.com/devicelogin"
    print("\n=== Sign in ===", flush=True)
    print(f"On any device with a browser, open:  {url}")
    print(f"and enter the code:                  {start['user_code']}")
    print("Sign in with the Outlook.com account and approve the request.")
    lifetime = int(start.get("expires_in", 900))
    print(f"This is NOT a hang: the script waits up to {lifetime // 60} minutes for you to enter the "
          "code. Press Ctrl-C to stop.", flush=True)

    interval = int(start.get("interval", 5))
    began = time.monotonic()
    deadline = began + lifetime
    next_note = began + 30
    while time.monotonic() < deadline:
        time.sleep(interval)
        if time.monotonic() >= next_note:
            print(f"[{time.strftime('%H:%M:%S')}] still waiting for the sign-in "
                  f"({int(time.monotonic() - began)}s)...", flush=True)
            next_note += 30
        result = post_form(
            f"{authority}/oauth2/v2.0/token",
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": start["device_code"],
            },
        )
        if "access_token" in result or "refresh_token" in result:
            print("Signed in.")
            return result
        error = result.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        text = describe_error(result)
        die(f"Sign-in failed: {text}\n  {hint_for(text)}".rstrip())
    die("The sign-in code expired before it was used. Run the script again.")


def refresh_access_token(authority: str, client_id: str, refresh_token: str, scope: str) -> dict:
    return post_form(
        f"{authority}/oauth2/v2.0/token",
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
            "scope": scope,
        },
    )


# --------------------------------------------------------------------------
# Token cache (refresh token only)
# --------------------------------------------------------------------------

def load_cache(path: Path, client_id: str, authority: str) -> str | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if data.get("client_id") != client_id or data.get("authority") != authority:
        return None
    return data.get("refresh_token")


def save_cache(path: Path, client_id: str, authority: str, refresh_token: str) -> None:
    payload = json.dumps({"client_id": client_id, "authority": authority,
                          "refresh_token": refresh_token}).encode("utf-8")
    temp = path.with_name(path.name + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)
    os.chmod(path, 0o600)


# --------------------------------------------------------------------------
# Token inspection and the IMAP check
# --------------------------------------------------------------------------

def jwt_claims(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, json.JSONDecodeError):
        return None


def describe_token(token: str) -> str:
    claims = jwt_claims(token)
    if claims is None:
        return "opaque token (not a readable JWT)"
    pieces = [f"aud={claims.get('aud', '?')}"]
    if claims.get("scp"):
        pieces.append(f"scp={claims['scp']}")
    if claims.get("exp"):
        minutes = int((int(claims["exp"]) - time.time()) / 60)
        pieces.append(f"expires in ~{minutes} min")
    return "JWT " + ", ".join(pieces)


def try_imap(host: str, port: int, email: str, token: str,
             ca_file: str | None, timeout: float) -> tuple[bool, str]:
    context = ssl.create_default_context(cafile=ca_file)
    step(f"Connecting to IMAP {host}:{port}")
    try:
        conn = imaplib.IMAP4_SSL(host, port, ssl_context=context, timeout=timeout)
    except (OSError, imaplib.IMAP4.error) as exc:
        return False, f"could not connect to {host}:{port}: {exc}"

    challenges: list[str] = []
    auth_string = f"user={email}\x01auth=Bearer {token}\x01\x01"

    def authobject(challenge):
        # First call: send credentials. If the server answers with an error
        # challenge, record it and send an empty line, which ends the exchange.
        if not challenges and not getattr(authobject, "sent", False):
            authobject.sent = True
            return auth_string
        challenges.append(challenge.decode("utf-8", "replace") if challenge else "")
        return ""

    try:
        if "AUTH=XOAUTH2" not in conn.capabilities:
            note = " (server did not advertise AUTH=XOAUTH2)"
        else:
            note = ""
        step("IMAP connected; sending AUTHENTICATE XOAUTH2")
        try:
            conn.authenticate("XOAUTH2", authobject)
        except imaplib.IMAP4.error as exc:
            detail = " ".join(a.decode("utf-8", "replace") if isinstance(a, bytes) else str(a)
                              for a in exc.args)
            if challenges and challenges[0]:
                detail += f" | server detail: {challenges[0][:200]}"
            return False, f"AUTHENTICATE rejected: {detail}{note}"
        _typ, folders = conn.list()
        folder_count = len([f for f in folders or [] if f])
        typ, data = conn.select("INBOX", readonly=True)
        inbox = int(data[0]) if typ == "OK" and data and data[0] else 0
        return True, f"authenticated; {folder_count} folders; INBOX has {inbox:,} messages{note}"
    except (OSError, imaplib.IMAP4.error) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        try:
            conn.logout()
        except Exception:
            pass


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Check which OAuth2 scope Outlook.com IMAP accepts (headless device-code sign-in).",
    )
    p.add_argument("--client-id", default=os.environ.get("MS_CLIENT_ID"),
                   help="Application (client) ID of your Entra app (or set MS_CLIENT_ID)")
    p.add_argument("--email", default=os.environ.get("MS_EMAIL"),
                   help="The Outlook.com address (or set MS_EMAIL)")
    p.add_argument("--authority", default="consumers",
                   help="consumers (default, personal accounts), common, or a tenant ID")
    p.add_argument("--login-scope", choices=sorted(SCOPE_VARIANTS), default="outlook",
                   help="scope variant to request at sign-in (default: outlook)")
    p.add_argument("--try", dest="variants", default=",".join(SCOPE_VARIANTS),
                   help="comma-separated variants to test (default: all)")
    p.add_argument("--cache", default="~/.ms_oauth_test_token.json",
                   help="where the refresh token is saved (default: %(default)s)")
    p.add_argument("--no-cache", action="store_true", help="do not read or save a refresh token")
    p.add_argument("--forget", action="store_true", help="delete the saved refresh token and exit")
    p.add_argument("--imap-host", default="outlook.office365.com")
    p.add_argument("--imap-port", type=int, default=993)
    p.add_argument("--ca-file", help="extra CA certificate file (only for testing against a fake server)")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--ipv4", action="store_true",
                   help="use IPv4 only (fixes hangs on networks with broken IPv6)")
    return p.parse_args()


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)
    args = parse_args()
    if args.ipv4:
        force_ipv4()
        print("Using IPv4 only.", flush=True)
    cache_path = Path(args.cache).expanduser()

    if args.forget:
        try:
            cache_path.unlink()
            print(f"Deleted {cache_path}")
        except FileNotFoundError:
            print(f"Nothing to delete at {cache_path}")
        return 0

    if not args.client_id:
        die("Provide --client-id (or MS_CLIENT_ID).")
    if not args.email:
        die("Provide --email (or MS_EMAIL).")
    variants = [v.strip() for v in args.variants.split(",") if v.strip()]
    unknown = [v for v in variants if v not in SCOPE_VARIANTS]
    if unknown or not variants:
        die(f"--try must list some of: {', '.join(SCOPE_VARIANTS)}")

    authority = f"{AUTHORITY_BASE}/{args.authority}"
    split = urllib.parse.urlsplit(AUTHORITY_BASE)
    if preflight("Microsoft sign-in", split.hostname,
                 split.port or (443 if split.scheme == "https" else 80)) and not args.ipv4:
        force_ipv4()
        print("    IPv6 does not work here but IPv4 does: switching to IPv4 only for this run.", flush=True)
    preflight("IMAP server", args.imap_host, args.imap_port)

    refresh_token = None if args.no_cache else load_cache(cache_path, args.client_id, args.authority)
    if refresh_token:
        print(f"Using the saved sign-in from {cache_path} (use --forget to remove it).")
    else:
        login = device_login(authority, args.client_id, SCOPE_VARIANTS[args.login_scope])
        refresh_token = login.get("refresh_token")
        if not refresh_token:
            die("Sign-in worked but no refresh token was returned. Check that offline_access "
                "is added as a delegated permission.")
        if not args.no_cache:
            save_cache(cache_path, args.client_id, args.authority, refresh_token)

    results = []
    for name in variants:
        print(f"\n--- Variant '{name}': {SCOPE_VARIANTS[name]}")
        response = refresh_access_token(authority, args.client_id, refresh_token, SCOPE_VARIANTS[name])
        if "access_token" not in response:
            text = describe_error(response)
            advice = hint_for(text)
            print(f"  token request FAILED: {text}")
            if advice:
                print(f"  hint: {advice}")
            results.append((name, False, "no token issued"))
            continue
        if response.get("refresh_token"):
            refresh_token = response["refresh_token"]
            if not args.no_cache:
                save_cache(cache_path, args.client_id, args.authority, refresh_token)
        token = response["access_token"]
        print(f"  token issued: {describe_token(token)}")
        ok, detail = try_imap(args.imap_host, args.imap_port, args.email, token,
                              args.ca_file, args.timeout)
        print(f"  IMAP: {'OK' if ok else 'FAILED'} - {detail}")
        results.append((name, ok, detail))

    print("\n=== Summary ===")
    for name, ok, detail in results:
        print(f"  {name:8s} {'WORKS' if ok else 'fails':6s} {detail[:90]}")
    working = [name for name, ok, _ in results if ok]
    if working:
        best = working[0]
        print(f"\nUse IMAP_OAUTH_SCOPES=\"{SCOPE_VARIANTS[best]}\"")
        if best != args.login_scope:
            print(f"Note: sign-in used '{args.login_scope}' and the working token was obtained by "
                  f"refreshing with '{best}'. The importer must do the same two-step request.")
        print("Tell me which variant(s) worked and I'll build the importer around it.")
        return 0
    print("\nNo variant authenticated. Send me the output above (it contains no secrets) and the "
          "exact error text, and we'll work out the next step.")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(f"\nStopped with Ctrl-C while: {CURRENT_STEP}", file=sys.stderr)
        raise SystemExit(130)
