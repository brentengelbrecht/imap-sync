#!/usr/bin/env python3
"""
Generic IMAP4-to-local email repository importer.

The local repository is authoritative. The IMAP server is only an import source.

Repository ownership model (same philosophy as the Gmail importer):
- The messages table is the canonical ALL collection.
- ALL membership is permanent and implicit.
- Every distinct message is stored exactly once, as the raw RFC 822 bytes
  returned by the server. Identity is the SHA-256 of those bytes, because a
  generic IMAP server has no global message ID (a UID is only meaningful
  inside one folder and one UIDVALIDITY epoch).
- Local folders are organisational references to canonical message records,
  never separate physical copies.
- Server-side deletions, moves and flag changes never delete local data.
- Only explicit local deletion removes a message from ALL, and it leaves a
  tombstone so the message is not re-imported.

The server is accessed strictly read-only: folders are opened with EXAMINE
and message bodies are fetched with BODY.PEEK[], so \\Seen is never set.

Two login types:
  - Regular IMAP: username + password (IMAP_AUTH=password, the default). Works with
    any IMAP4 server that accepts passwords.
  - Outlook.com OAuth: IMAP_AUTH=microsoft-oauth2. Microsoft-specific: it uses
    Microsoft's sign-in endpoints and a device-code sign-in done once by --authorise.
    It does not work with Gmail, Yahoo or any other provider's OAuth.

Configuration is supplied through environment variables. Run with --help
for the full list.
"""

from __future__ import annotations

import argparse
import base64
import email.parser
import errno
import hashlib
import imaplib
import json
import logging
import os
import random
import re
import shutil
import socket
import sqlite3
import ssl
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import quote

APP_NAME = "IMAP Local Repository Importer"
REPOSITORY_APPLICATION = "imap-local-repository"
SCHEMA_VERSION = 1
MAX_FILES_PER_SHARD = 500
DEFAULT_DB_LOCATION = "./data"
REPOSITORY_MARKER = "repository.json"
DATABASE_FILENAME = "repository.db"
DEFAULT_MIN_FREE_BYTES = 64 * 1024 * 1024
DEFAULT_HTTP_TIMEOUT_SECONDS = 30  # socket timeout for every IMAP operation
MAX_RETRIES = 8
INITIAL_BACKOFF_SECONDS = 2.0
MAX_BACKOFF_SECONDS = 120.0
THROTTLED_MIN_INTERVAL_SECONDS = 0.5
MAX_REQUEST_INTERVAL_SECONDS = 5.0
INTERVAL_RECOVERY_SUCCESSES = 40

# imaplib refuses any single response line over 1,000,000 bytes. UID SEARCH ALL
# on a large folder is one long line, so raise the limit.
imaplib._MAXLINE = 50 * 1024 * 1024

# Server responses (NO/BYE text) that suggest "try again later", not "this
# request is wrong". Matched case-insensitively.
TRANSIENT_RESPONSE_MARKERS = (
    "THROTTLE", "UNAVAILABLE", "TOO MANY", "TRY AGAIN", "TEMPORAR",
    "RATE LIMIT", "SERVER BUSY", "IN USE",
)


class DiskSpaceExhausted(RuntimeError):
    """Fatal repository storage condition; stop the import immediately."""


class ImapRetryExhausted(RuntimeError):
    """The server kept failing/throttling after bounded exponential backoff."""


class ImapAuthError(RuntimeError):
    """Login was rejected. Never retried."""


class ImapCommandError(RuntimeError):
    """The server rejected one command (not transient)."""


class TokenRefreshError(OSError):
    """Transient failure obtaining an OAuth access token; retried with backoff."""


class _TokenRejected(Exception):
    """Internal: the server refused a cached access token; refresh and retry."""


class _TransientResponse(Exception):
    """Internal: a NO/BYE response that looks like throttling or overload."""


# --------------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------------

def interruptible_wait(seconds: float) -> None:
    """Wait without masking Ctrl-C."""
    deadline = time.monotonic() + max(0.0, seconds)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.25, remaining))


def minimum_free_bytes() -> int:
    raw = os.environ.get("IMAP_MIN_FREE_BYTES", str(DEFAULT_MIN_FREE_BYTES))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("IMAP_MIN_FREE_BYTES must be a non-negative integer.") from exc
    if value < 0:
        raise ValueError("IMAP_MIN_FREE_BYTES must be a non-negative integer.")
    return value


def check_disk_space(path: Path) -> None:
    """Keep a configurable free-space reserve before writing more data."""
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    usage = shutil.disk_usage(probe)
    reserve = minimum_free_bytes()
    if usage.free < reserve:
        raise DiskSpaceExhausted(
            f"Insufficient disk space at {probe}: {usage.free:,} bytes free; "
            f"the configured safety reserve is {reserve:,} bytes. "
            "The import has stopped. Free space and run it again to resume. "
            "Set IMAP_MIN_FREE_BYTES=0 to disable the reserve check."
        )


def is_disk_full_error(exc: BaseException) -> bool:
    if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
        return True
    if isinstance(exc, sqlite3.Error):
        return getattr(exc, "sqlite_errorcode", None) == getattr(sqlite3, "SQLITE_FULL", 13)
    return False


def _warn_if_permissive_permissions(path: Path, description: str) -> None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            logging.warning(
                "%s permissions are broader than owner-only. Consider: chmod 600 %s",
                description, path,
            )
    except OSError:
        logging.debug("Could not inspect %s permissions.", description)


def required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise ValueError(f"Required environment variable {name} is not set.")
    return value.strip()


def safe_repository_name(name: str) -> str:
    encoded = quote(name, safe="") or "user"
    if encoded in (".", ".."):
        encoded = encoded.replace(".", "%2E")
    return encoded


# --------------------------------------------------------------------------
# IMAP folder names (modified UTF-7, RFC 3501 section 5.1.3)
# --------------------------------------------------------------------------

def decode_imap_utf7(value: str) -> str:
    """Decode an IMAP modified-UTF-7 mailbox name for display/storage."""
    def replace(match: re.Match) -> str:
        chunk = match.group(1)
        if chunk == "":
            return "&"
        data = chunk.replace(",", "/")
        data += "=" * (-len(data) % 4)
        return base64.b64decode(data).decode("utf-16-be")

    try:
        return re.sub(r"&([^-]*)-", replace, value)
    except (ValueError, UnicodeDecodeError):
        return value


def quote_mailbox(imap_name: str) -> str:
    """Quote a raw (already modified-UTF-7) mailbox name as an IMAP string."""
    return '"' + imap_name.replace("\\", "\\\\").replace('"', '\\"') + '"'


_LIST_RE = re.compile(
    r'^\((?P<flags>[^)]*)\)\s+(?P<delim>"(?:[^"\\]|\\.)*"|NIL)\s+(?P<name>.+)$',
    re.DOTALL,
)


def parse_list_item(item) -> Optional[dict]:
    """Parse one LIST response element (bytes, or a (header, literal) tuple)."""
    if item is None:
        return None
    literal = None
    if isinstance(item, tuple):
        head, literal = item[0], item[1]
    else:
        head = item
    text = head.decode("utf-8", errors="replace") if isinstance(head, bytes) else str(head)
    if literal is not None:
        # "(flags) "/" {12}" followed by the literal holding the name.
        text = re.sub(r"\s*\{\d+\}\s*$", "", text)
        match = _LIST_RE.match(text + " x")
        if not match:
            return None
        name = literal.decode("utf-8", errors="replace")
    else:
        match = _LIST_RE.match(text.strip())
        if not match:
            return None
        name = match.group("name").strip()
        if name.startswith('"') and name.endswith('"') and len(name) >= 2:
            name = re.sub(r"\\(.)", r"\1", name[1:-1])
    delim = match.group("delim")
    delimiter = None if delim == "NIL" else re.sub(r"\\(.)", r"\1", delim[1:-1])
    flags = {f.casefold() for f in match.group("flags").split()}
    return {
        "imap_name": name,
        "name": decode_imap_utf7(name),
        "delimiter": delimiter,
        "flags": flags,
    }


def parse_fetch_response(data, uid: int) -> Optional[dict]:
    """Extract body, flags and INTERNALDATE from a single-UID FETCH response.

    Returns None when the server returned no message body (for example the
    message was expunged between SEARCH and FETCH).
    """
    for index, item in enumerate(data or []):
        if not (isinstance(item, tuple) and len(item) >= 2
                and isinstance(item[1], (bytes, bytearray))):
            continue
        meta = bytes(item[0])
        # Some servers send FLAGS/UID after the literal, in the next element.
        if index + 1 < len(data) and isinstance(data[index + 1], (bytes, bytearray)):
            meta += b" " + bytes(data[index + 1])
        uid_match = re.search(rb"\bUID (\d+)", meta)
        if uid_match and int(uid_match.group(1)) != uid:
            continue

        flags: set[str] = set()
        flags_match = re.search(rb"FLAGS \(([^)]*)\)", meta)
        if flags_match:
            flags = {f.decode("ascii", "replace").casefold()
                     for f in flags_match.group(1).split()}

        internal_date = None
        date_match = re.search(rb'INTERNALDATE "([^"]+)"', meta)
        if date_match:
            try:
                parsed = datetime.strptime(
                    date_match.group(1).decode("ascii").strip(),
                    "%d-%b-%Y %H:%M:%S %z",
                )
                internal_date = parsed.astimezone(timezone.utc).isoformat()
            except (ValueError, UnicodeDecodeError):
                internal_date = date_match.group(1).decode("ascii", "replace")

        return {"raw": bytes(item[1]), "flags": flags, "internal_date": internal_date}
    return None


# --------------------------------------------------------------------------
# Network preference: IPv4 fallback when IPv6 is unusable
# --------------------------------------------------------------------------

_ORIGINAL_GETADDRINFO = socket.getaddrinfo


def force_ipv4() -> None:
    """Make every later connection in this process use IPv4 only."""
    socket.getaddrinfo = lambda *a, **k: [
        info for info in _ORIGINAL_GETADDRINFO(*a, **k) if info[0] == socket.AF_INET
    ]


def ipv6_unusable(host: str, port: int, timeout: float = 5.0) -> bool:
    """True when the host has IPv6 and IPv4 addresses, IPv6 fails and IPv4 works.

    Python tries each IPv6 address in turn and waits out the full timeout on each,
    which makes a network with broken IPv6 look like a hang.
    """
    try:
        infos = _ORIGINAL_GETADDRINFO(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False
    v6 = [i for i in infos if i[0] == socket.AF_INET6]
    v4 = [i for i in infos if i[0] == socket.AF_INET]
    if not v6 or not v4:
        return False

    def connects(info) -> bool:
        try:
            with socket.create_connection(info[4][:2], timeout=timeout):
                return True
        except OSError:
            return False

    return (not connects(v6[0])) and connects(v4[0])


def apply_network_preference(config: dict) -> None:
    mode = config["ipv4_only"]
    if mode == "false":
        return
    if mode == "true":
        force_ipv4()
        logging.info("IPv4 only (IMAP_IPV4_ONLY=true).")
        return
    targets = [(config["host"], config["port"])]
    if config["auth"] == "microsoft-oauth2":
        login = urllib.parse.urlsplit(MS_LOGIN_BASE)
        targets.append((login.hostname, login.port or (443 if login.scheme == "https" else 80)))
    for host, port in targets:
        if ipv6_unusable(host, port):
            force_ipv4()
            logging.info("IPv6 to %s does not work but IPv4 does; using IPv4 only.", host)
            return


# --------------------------------------------------------------------------
# OAuth2 for personal Outlook.com accounts (device-code flow, XOAUTH2)
# --------------------------------------------------------------------------

# Overridable for testing against a mock token endpoint only.
MS_LOGIN_BASE = os.environ.get("IMAP_OAUTH_AUTHORITY_BASE", "https://login.microsoftonline.com")
DEFAULT_OAUTH_SCOPES = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
DEFAULT_OAUTH_HOST = "outlook.office365.com"
TOKEN_EXPIRY_MARGIN_SECONDS = 300
TRANSIENT_TOKEN_ERRORS = {"temporarily_unavailable", "server_error", "http_429"}


def _post_form(url: str, fields: dict, timeout: float = 30.0) -> tuple[int, dict]:
    data = urllib.parse.urlencode(fields).encode("ascii")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read().decode("utf-8", "replace")
    try:
        return status, json.loads(body)
    except json.JSONDecodeError:
        return status, {"error": f"http_{status}", "error_description": body[:200]}


def _describe_token_error(response: dict) -> str:
    text = f"{response.get('error', 'unknown_error')}: {response.get('error_description', '')}"
    return " ".join(text.split())[:300]


def write_private_file(path: Path, text: str) -> None:
    """Atomically write a file readable only by the owner."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    temp = path.with_name(path.name + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)
    os.chmod(path, 0o600)


class MicrosoftOAuth:
    """Access tokens for IMAP, from a refresh token saved by --authorise."""

    def __init__(self, client_id: str, tenant: str, scopes: str, token_file: Path):
        self.client_id = client_id
        self.tenant = tenant
        self.scopes = scopes
        self.token_file = token_file
        self.refresh_token: Optional[str] = None
        self._access_token: Optional[str] = None
        self._expires_at = 0.0
        self.token_is_fresh = False

    @property
    def authority(self) -> str:
        return f"{MS_LOGIN_BASE}/{self.tenant}"

    def save_refresh_token(self, refresh_token: str) -> None:
        self.refresh_token = refresh_token
        write_private_file(self.token_file, json.dumps({
            "client_id": self.client_id,
            "tenant": self.tenant,
            "scopes": self.scopes,
            "refresh_token": refresh_token,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2) + "\n")

    def _load(self) -> None:
        try:
            data = json.loads(self.token_file.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ImapAuthError(
                f"No saved sign-in found at {self.token_file}. Run this script with "
                "--authorise to sign in to the Microsoft account."
            ) from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise ImapAuthError(
                f"Cannot read the OAuth token file {self.token_file}: {exc}. "
                "Run with --authorise to create it again."
            ) from exc
        if data.get("client_id") != self.client_id or data.get("tenant") != self.tenant:
            raise ImapAuthError(
                f"{self.token_file} was created for a different IMAP_OAUTH_CLIENT_ID or "
                "IMAP_OAUTH_TENANT. Run with --authorise to sign in again."
            )
        if not data.get("refresh_token"):
            raise ImapAuthError(f"{self.token_file} holds no refresh token. Run with --authorise.")
        self.refresh_token = data["refresh_token"]
        _warn_if_permissive_permissions(self.token_file, "OAuth token file")

    def invalidate(self) -> None:
        self._access_token = None

    def access_token(self) -> str:
        """Return a usable access token, refreshing when missing or about to expire."""
        if self._access_token and time.time() < self._expires_at - TOKEN_EXPIRY_MARGIN_SECONDS:
            self.token_is_fresh = False
            return self._access_token
        if self.refresh_token is None:
            self._load()
        status, response = _post_form(
            f"{self.authority}/oauth2/v2.0/token",
            {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": self.refresh_token,
                "scope": self.scopes,
            },
        )
        if "access_token" not in response:
            error = str(response.get("error", ""))
            if error in TRANSIENT_TOKEN_ERRORS or error.startswith("http_5"):
                raise TokenRefreshError(f"token endpoint unavailable: {_describe_token_error(response)}")
            raise ImapAuthError(
                f"Microsoft refused to renew the sign-in ({_describe_token_error(response)}). "
                "Run this script with --authorise to sign in again."
            )
        self._access_token = response["access_token"]
        self._expires_at = time.time() + int(response.get("expires_in", 3600))
        self.token_is_fresh = True
        new_refresh = response.get("refresh_token")
        if new_refresh and new_refresh != self.refresh_token:
            self.save_refresh_token(new_refresh)
        return self._access_token

    def device_login(self) -> dict:
        """Interactive device-code sign-in. Returns the token response."""
        status, start = _post_form(
            f"{self.authority}/oauth2/v2.0/devicecode",
            {"client_id": self.client_id, "scope": self.scopes},
        )
        if "device_code" not in start:
            raise ImapAuthError(
                f"Could not start the sign-in: {_describe_token_error(start)}. Check "
                "IMAP_OAUTH_CLIENT_ID and that 'Allow public client flows' is enabled for the app."
            )
        url = start.get("verification_uri") or start.get("verification_url") or "https://microsoft.com/devicelogin"
        lifetime = int(start.get("expires_in", 900))
        print("\n=== Sign in ===")
        print(f"On any device with a browser, open:  {url}")
        print(f"and enter the code:                  {start['user_code']}")
        print("Sign in with the Outlook.com account and approve the request.")
        print(f"Waiting up to {lifetime // 60} minutes for you to finish (Ctrl-C to cancel)...",
              flush=True)
        interval = int(start.get("interval", 5))
        deadline = time.monotonic() + lifetime
        while time.monotonic() < deadline:
            interruptible_wait(interval)
            _status, result = _post_form(
                f"{self.authority}/oauth2/v2.0/token",
                {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": self.client_id,
                    "device_code": start["device_code"],
                },
            )
            if "access_token" in result:
                return result
            error = result.get("error")
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5
                continue
            raise ImapAuthError(f"Sign-in failed: {_describe_token_error(result)}")
        raise ImapAuthError("The sign-in code expired before it was used. Run --authorise again.")


def xoauth2_authenticate(conn: imaplib.IMAP4, username: str, access_token: str) -> None:
    """SASL XOAUTH2. Raises imaplib.IMAP4.error (with server detail) if rejected."""
    challenges: list[str] = []
    sent = [False]

    def authobject(challenge):
        if not sent[0]:
            sent[0] = True
            return f"user={username}\x01auth=Bearer {access_token}\x01\x01"
        # The server sent an error challenge: record it and end the exchange.
        challenges.append(challenge.decode("utf-8", "replace") if challenge else "")
        return ""

    try:
        conn.authenticate("XOAUTH2", authobject)
    except imaplib.IMAP4.error as exc:
        detail = " ".join(a.decode("utf-8", "replace") if isinstance(a, bytes) else str(a)
                          for a in exc.args)
        if challenges and challenges[0]:
            detail += f" (server detail: {challenges[0][:200]})"
        raise imaplib.IMAP4.error(detail) from exc


def run_authorise(config: dict) -> int:
    """One-time interactive sign-in; saves the token only if IMAP login then works."""
    if config["auth"] != "microsoft-oauth2":
        raise ValueError("--authorise is only for Outlook.com accounts: set IMAP_AUTH=microsoft-oauth2.")
    oauth: MicrosoftOAuth = config["oauth"]
    result = oauth.device_login()
    refresh_token = result.get("refresh_token")
    if not refresh_token:
        raise ImapAuthError(
            "Sign-in worked but Microsoft returned no refresh token. Make sure "
            "'offline_access' is added as a delegated permission on the app."
        )
    print("Signed in. Checking that this account can use IMAP...", flush=True)

    context = ssl.create_default_context(cafile=config.get("ca_file"))
    conn = imaplib.IMAP4_SSL(host=config["host"], port=config["port"],
                             ssl_context=context, timeout=DEFAULT_HTTP_TIMEOUT_SECONDS)
    try:
        try:
            xoauth2_authenticate(conn, config["username"], result["access_token"])
        except imaplib.IMAP4.error as exc:
            raise ImapAuthError(
                f"The server rejected the new sign-in ({exc}). Check that you signed in as "
                f"{config['username']!r}, that IMAP is enabled for the mailbox, and that the "
                "app has the IMAP.AccessAsUser.All permission. Nothing was saved."
            ) from exc
        typ, folders = conn.list()
        count = len([f for f in folders or [] if f]) if typ == "OK" else 0
    finally:
        try:
            conn.logout()
        except Exception:
            pass

    oauth.save_refresh_token(refresh_token)
    print(f"Success: {config['username']} can use IMAP ({count} folders). "
          f"Sign-in saved to {oauth.token_file} (owner-only).")
    print("You can now run the importer without --authorise. Keep that file private.")
    return 0


# --------------------------------------------------------------------------
# IMAP session with reconnect, backoff and optional adaptive pacing
# --------------------------------------------------------------------------

class ImapSession:
    """One logical IMAP connection that survives drops and throttling.

    Every command goes through call(), which reconnects (and re-selects the
    current folder) after connection failures and backs off after throttling
    responses, up to MAX_RETRIES retries. Authentication failures and TLS
    certificate failures are never retried.
    """

    def __init__(self, config: dict):
        self.config = config
        self.conn: Optional[imaplib.IMAP4] = None
        self.selected: Optional[str] = None
        self.selected_uidvalidity: Optional[str] = None
        self.base_interval = float(config.get("request_interval", 0.0))
        self.interval = self.base_interval
        self._successes = 0
        self._last_started = 0.0

    # -- pacing ----------------------------------------------------------
    def _pace(self) -> None:
        wait = self.interval - (time.monotonic() - self._last_started)
        if wait > 0:
            interruptible_wait(wait)
        self._last_started = time.monotonic()

    def _note_success(self) -> None:
        self._successes += 1
        if self._successes >= INTERVAL_RECOVERY_SUCCESSES:
            self._successes = 0
            if self.interval > self.base_interval:
                self.interval = max(self.base_interval, self.interval * 0.9)

    def _note_throttle(self) -> None:
        self._successes = 0
        self.interval = min(
            MAX_REQUEST_INTERVAL_SECONDS,
            max(THROTTLED_MIN_INTERVAL_SECONDS, self.interval * 2),
        )

    # -- connection ------------------------------------------------------
    def _open(self) -> None:
        cfg = self.config
        oauth: Optional[MicrosoftOAuth] = cfg.get("oauth")
        # Get the token first: a token problem must not leave a connection open.
        access_token = oauth.access_token() if oauth else None
        context = ssl.create_default_context(cafile=cfg.get("ca_file"))
        timeout = DEFAULT_HTTP_TIMEOUT_SECONDS
        conn: Optional[imaplib.IMAP4] = None
        try:
            if cfg["security"] == "ssl":
                conn = imaplib.IMAP4_SSL(
                    host=cfg["host"], port=cfg["port"],
                    ssl_context=context, timeout=timeout,
                )
            else:
                conn = imaplib.IMAP4(host=cfg["host"], port=cfg["port"], timeout=timeout)
                if "STARTTLS" not in conn.capabilities:
                    raise RuntimeError(
                        f"{cfg['host']}:{cfg['port']} does not offer STARTTLS. "
                        "Refusing to send credentials unencrypted."
                    )
                conn.starttls(ssl_context=context)
            if oauth is not None:
                try:
                    xoauth2_authenticate(conn, cfg["username"], access_token)
                except imaplib.IMAP4.error as exc:
                    text = str(exc)
                    if any(marker in text.upper() for marker in TRANSIENT_RESPONSE_MARKERS):
                        raise _TransientResponse(text) from exc
                    if not oauth.token_is_fresh:
                        oauth.invalidate()
                        raise _TokenRejected(text) from exc
                    raise ImapAuthError(
                        f"The server rejected a freshly issued OAuth token for "
                        f"{cfg['username']!r}: {text}. Check that IMAP is enabled for the "
                        "mailbox and that this is the account you signed in with; if in "
                        "doubt run --authorise again."
                    ) from exc
            else:
                try:
                    conn.login(cfg["username"], cfg["password"])
                except imaplib.IMAP4.error as exc:
                    text = " ".join(
                        a.decode("utf-8", "replace") if isinstance(a, bytes) else str(a)
                        for a in exc.args
                    )
                    if any(marker in text.upper() for marker in TRANSIENT_RESPONSE_MARKERS):
                        raise _TransientResponse(text) from exc
                    raise ImapAuthError(
                        f"The server rejected the login for {cfg['username']!r}: {text}. "
                        "Check the username and password. Many providers require an "
                        "app-specific password or IMAP to be enabled for the account."
                    ) from exc
        except BaseException:
            if conn is not None:
                self._close_quietly(conn)
            raise
        self.conn = conn
        logging.info("Connected to %s:%s as %s.", cfg["host"], cfg["port"], cfg["username"])

        if self.selected is not None:
            typ, data = conn.select(quote_mailbox(self.selected), readonly=True)
            if typ != "OK":
                raise ImapCommandError(f"Could not re-open folder after reconnect: {data}")
            uidvalidity = self._read_uidvalidity(conn)
            if uidvalidity != self.selected_uidvalidity:
                raise ImapCommandError(
                    "UIDVALIDITY changed while the import was running; "
                    "the folder will be retried on the next run."
                )

    @staticmethod
    def _read_uidvalidity(conn: imaplib.IMAP4) -> Optional[str]:
        _typ, values = conn.response("UIDVALIDITY")
        if values and values[0]:
            return values[0].decode("ascii", "replace") if isinstance(values[0], bytes) else str(values[0])
        return None

    @staticmethod
    def _close_quietly(conn: imaplib.IMAP4) -> None:
        try:
            conn.logout()
        except Exception:
            try:
                conn.shutdown()
            except Exception:
                pass

    def _drop(self) -> None:
        if self.conn is not None:
            self._close_quietly(self.conn)
        self.conn = None

    def close(self) -> None:
        self._drop()

    # -- command execution -----------------------------------------------
    def call(self, description: str,
             func: Callable[[imaplib.IMAP4], tuple]):
        """Run func(conn) -> (typ, data); return data when typ is OK."""
        for attempt in range(MAX_RETRIES + 1):
            self._pace()
            try:
                if self.conn is None:
                    self._open()
                typ, data = func(self.conn)
                if typ != "OK":
                    text = " ".join(
                        d.decode("utf-8", "replace") if isinstance(d, bytes) else str(d)
                        for d in (data or []) if d
                    )
                    if any(m in text.upper() for m in TRANSIENT_RESPONSE_MARKERS):
                        raise _TransientResponse(text)
                    raise ImapCommandError(f"{description}: server replied {typ} {text}".strip())
                self._note_success()
                return data
            except (ImapAuthError, ImapCommandError):
                raise
            except ssl.SSLCertVerificationError as exc:
                self._drop()
                raise RuntimeError(
                    f"TLS certificate verification failed for {self.config['host']}: {exc}. "
                    "If the server uses a private certificate authority, set "
                    "IMAP_CA_FILE to its PEM file."
                ) from exc
            except _TokenRejected as exc:
                reason = f"cached OAuth token was rejected ({exc}); fetching a new one"
            except _TransientResponse as exc:
                self._note_throttle()
                reason = f"server asked to slow down ({exc})"
            except (imaplib.IMAP4.abort, OSError, EOFError) as exc:
                if is_disk_full_error(exc):
                    raise
                self._drop()
                reason = f"{type(exc).__name__}: {exc}"

            if attempt >= MAX_RETRIES:
                raise ImapRetryExhausted(
                    f"IMAP server kept failing for {description} after "
                    f"{MAX_RETRIES + 1} attempts (last problem: {reason}). The import "
                    "has stopped; run it again later to resume."
                )
            delay = min(MAX_BACKOFF_SECONDS, INITIAL_BACKOFF_SECONDS * (2 ** attempt))
            delay *= random.uniform(0.8, 1.2)
            logging.warning(
                "IMAP problem during %s: %s; retry %s/%s in %.1f seconds.",
                description, reason, attempt + 1, MAX_RETRIES, delay,
            )
            interruptible_wait(delay)
        raise AssertionError("unreachable")  # pragma: no cover

    # -- operations ------------------------------------------------------
    def list_folders(self) -> list[dict]:
        data = self.call("folder listing", lambda c: c.list())
        folders = []
        for item in data:
            parsed = parse_list_item(item)
            if parsed is None:
                if item:
                    logging.warning("Could not parse LIST response line: %r", item)
                continue
            folders.append(parsed)
        return folders

    def select_folder(self, imap_name: str) -> tuple[int, str]:
        """Open a folder read-only (EXAMINE). Returns (message count, UIDVALIDITY)."""
        self.selected = None
        self.selected_uidvalidity = None

        def do_select(conn):
            typ, data = conn.select(quote_mailbox(imap_name), readonly=True)
            if typ == "OK":
                uidvalidity = self._read_uidvalidity(conn)
                return typ, [data[0], uidvalidity]
            return typ, data

        data = self.call(f"opening folder {imap_name!r}", do_select)
        exists = int(data[0]) if data[0] else 0
        uidvalidity = data[1]
        if not uidvalidity:
            raise ImapCommandError(
                f"Folder {imap_name!r} did not report UIDVALIDITY; its UIDs cannot be trusted."
            )
        self.selected = imap_name
        self.selected_uidvalidity = uidvalidity
        return exists, uidvalidity

    def search_all_uids(self) -> list[int]:
        data = self.call("UID SEARCH ALL", lambda c: c.uid("SEARCH", None, "ALL"))
        if not data or not data[0]:
            return []
        return sorted(int(token) for token in data[0].split())

    def fetch_message(self, uid: int) -> Optional[dict]:
        data = self.call(
            f"fetching UID {uid}",
            lambda c: c.uid("FETCH", str(uid), "(UID FLAGS INTERNALDATE BODY.PEEK[])"),
        )
        return parse_fetch_response(data, uid)


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def _split_names(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def read_password() -> str:
    password_file = os.environ.get("IMAP_PASSWORD_FILE", "").strip()
    if password_file:
        path = Path(password_file).expanduser()
        if not path.is_file():
            raise ValueError(f"IMAP_PASSWORD_FILE not found: {path}")
        _warn_if_permissive_permissions(path, "Password file")
        text = path.read_text(encoding="utf-8")
        password = text.rstrip("\r\n")
        if not password:
            raise ValueError(f"IMAP_PASSWORD_FILE is empty: {path}")
        return password
    password = os.environ.get("IMAP_PASSWORD", "")
    if not password:
        raise ValueError("Set IMAP_PASSWORD_FILE (preferred) or IMAP_PASSWORD.")
    return password


def _boolean_choice(name: str, default: str) -> str:
    value = os.environ.get(name, default).strip().casefold() or default
    mapping = {"true": "true", "yes": "true", "1": "true", "on": "true",
               "false": "false", "no": "false", "0": "false", "off": "false", "auto": "auto"}
    if value not in mapping:
        raise ValueError(f"{name} must be auto, true or false.")
    return mapping[value]


def get_configuration() -> dict:
    auth = os.environ.get("IMAP_AUTH", "password").strip().casefold() or "password"
    if auth == "oauth2":
        raise ValueError(
            "IMAP_AUTH=oauth2 has been renamed to IMAP_AUTH=microsoft-oauth2, because the "
            "OAuth support is specific to Microsoft (Outlook.com) accounts."
        )
    if auth not in ("password", "microsoft-oauth2"):
        raise ValueError("IMAP_AUTH must be 'password' (default) or 'microsoft-oauth2'.")
    if auth == "microsoft-oauth2":
        host = os.environ.get("IMAP_HOST", "").strip() or DEFAULT_OAUTH_HOST
    else:
        host = required_environment("IMAP_HOST")
    username = required_environment("IMAP_USERNAME")
    security = os.environ.get("IMAP_SECURITY", "ssl").strip().casefold()
    if security not in ("ssl", "starttls"):
        raise ValueError("IMAP_SECURITY must be 'ssl' (default, port 993) or 'starttls' (port 143).")

    port_text = os.environ.get("IMAP_PORT", "").strip()
    try:
        port = int(port_text) if port_text else (993 if security == "ssl" else 143)
    except ValueError as exc:
        raise ValueError("IMAP_PORT must be an integer.") from exc

    interval_text = os.environ.get("IMAP_REQUEST_INTERVAL", "0").strip() or "0"
    try:
        request_interval = float(interval_text)
    except ValueError as exc:
        raise ValueError("IMAP_REQUEST_INTERVAL must be a number of seconds.") from exc
    if request_interval < 0:
        raise ValueError("IMAP_REQUEST_INTERVAL must not be negative.")

    ca_file = os.environ.get("IMAP_CA_FILE", "").strip()
    if ca_file and not Path(ca_file).expanduser().is_file():
        raise ValueError(f"IMAP_CA_FILE not found: {ca_file}")

    password = None
    oauth = None
    if auth == "password":
        password = read_password()
    else:
        client_id = required_environment("IMAP_OAUTH_CLIENT_ID")
        tenant = os.environ.get("IMAP_OAUTH_TENANT", "consumers").strip() or "consumers"
        scopes = os.environ.get("IMAP_OAUTH_SCOPES", "").strip() or DEFAULT_OAUTH_SCOPES
        token_text = os.environ.get("IMAP_OAUTH_TOKEN_FILE", "").strip()
        token_file = (Path(token_text).expanduser() if token_text else
                      Path("~/.config/imap-local-repository").expanduser()
                      / (safe_repository_name(username) + ".oauth.json"))
        oauth = MicrosoftOAuth(client_id, tenant, scopes, token_file)

    db_location = Path(os.environ.get("DB_LOCATION", DEFAULT_DB_LOCATION)).expanduser()
    repo_name = os.environ.get("IMAP_REPOSITORY_NAME", "").strip() or username
    repository_path = db_location / safe_repository_name(repo_name)

    return {
        "auth": auth,
        "host": host,
        "port": port,
        "security": security,
        "username": username,
        "password": password,
        "oauth": oauth,
        "ipv4_only": _boolean_choice("IMAP_IPV4_ONLY", "auto"),
        "ca_file": str(Path(ca_file).expanduser()) if ca_file else None,
        "request_interval": request_interval,
        "include_folders": _split_names(os.environ.get("IMAP_FOLDERS", "")),
        "exclude_folders": _split_names(os.environ.get("IMAP_EXCLUDE_FOLDERS", "")),
        "db_location": db_location,
        "repository_path": repository_path,
        "database_path": repository_path / DATABASE_FILENAME,
    }


def _name_matches(name: str, patterns: list[str]) -> bool:
    folded = name.casefold()
    for pattern in patterns:
        wanted = pattern.casefold()
        if wanted.endswith("*"):
            if folded.startswith(wanted[:-1]):
                return True
        elif folded == wanted:
            return True
    return False


def choose_folders(folders: list[dict], include: list[str], exclude: list[str]) -> list[dict]:
    """Apply \\Noselect filtering and the include/exclude settings."""
    selectable = [
        f for f in folders
        if "\\noselect" not in f["flags"] and "\\nonexistent" not in f["flags"]
    ]
    if include:
        for pattern in include:
            if not any(_name_matches(f["name"], [pattern]) for f in selectable):
                logging.warning("IMAP_FOLDERS entry %r matched no selectable folder.", pattern)
        selectable = [f for f in selectable if _name_matches(f["name"], include)]
    if exclude:
        selectable = [f for f in selectable if not _name_matches(f["name"], exclude)]
    return selectable


# --------------------------------------------------------------------------
# Repository (SQLite + sharded .eml files)
# --------------------------------------------------------------------------

def detect_repository_mode(repository_path: Path) -> str:
    """Return initial/sync mode, rejecting incomplete or unknown directories."""
    if not repository_path.exists():
        return "initial"
    if not repository_path.is_dir():
        raise RuntimeError(f"Repository target exists but is not a directory: {repository_path}")
    if not list(repository_path.iterdir()):
        return "initial"

    marker = repository_path / REPOSITORY_MARKER
    database = repository_path / DATABASE_FILENAME
    messages = repository_path / "messages"
    if not marker.is_file() or not database.is_file() or not messages.is_dir():
        raise RuntimeError(
            "The target directory is non-empty but is not a complete recognised "
            f"repository: {repository_path}. Nothing has been changed."
        )
    try:
        with marker.open("r", encoding="utf-8") as handle:
            metadata = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read repository marker {marker}: {exc}") from exc

    if metadata.get("application") != REPOSITORY_APPLICATION:
        raise RuntimeError(
            f"Unrecognised repository marker: {marker} "
            f"(application {metadata.get('application')!r}; this script handles "
            f"{REPOSITORY_APPLICATION!r} repositories only)."
        )
    version = metadata.get("schema_version")
    if version != SCHEMA_VERSION:
        raise RuntimeError(
            f"Unsupported repository schema version {version!r}; "
            f"this script supports version {SCHEMA_VERSION}."
        )
    return "sync"


def write_repository_marker(repository_path: Path, config: dict) -> None:
    marker_path = repository_path / REPOSITORY_MARKER
    created_at = datetime.now(timezone.utc).isoformat()
    if marker_path.is_file():
        try:
            with marker_path.open("r", encoding="utf-8") as existing:
                created_at = json.load(existing).get("created_at", created_at)
        except (OSError, json.JSONDecodeError):
            pass
    marker = {
        "application": REPOSITORY_APPLICATION,
        "schema_version": SCHEMA_VERSION,
        "host": config["host"],
        "username": config["username"],
        "created_at": created_at,
    }
    temp_path = repository_path / (REPOSITORY_MARKER + ".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(marker, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, marker_path)


def connect_database(database_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


@contextmanager
def transaction(connection: sqlite3.Connection):
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


def create_schema(connection: sqlite3.Connection, config: dict) -> None:
    connection.executescript(
        """
        CREATE TABLE repository_info (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        -- Local folders. They start as copies of the server's folders and
        -- are afterwards owned by the local repository.
        CREATE TABLE folders (
            folder_id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,          -- decoded, human-readable
            imap_name TEXT,                     -- raw name used on the wire
            delimiter TEXT,
            uidvalidity TEXT,                   -- latest epoch seen
            last_seen_at TEXT,
            last_synced_at TEXT
        );

        CREATE TABLE message_shards (
            shard_id INTEGER PRIMARY KEY AUTOINCREMENT,
            directory_name TEXT NOT NULL UNIQUE,
            file_count INTEGER NOT NULL DEFAULT 0
                CHECK(file_count >= 0 AND file_count <= 500),
            created_at TEXT NOT NULL
        );

        -- The canonical ALL collection. Identity is the SHA-256 of the raw bytes.
        CREATE TABLE messages (
            message_id INTEGER PRIMARY KEY,
            sha256 TEXT NOT NULL UNIQUE,
            rfc822_message_id TEXT,
            shard_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            message_size INTEGER NOT NULL,
            internal_date TEXT,
            imported_at TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            is_starred INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(shard_id) REFERENCES message_shards(shard_id)
        );

        CREATE TABLE folder_messages (
            folder_id INTEGER NOT NULL,
            message_id INTEGER NOT NULL,
            first_seen_at TEXT NOT NULL,
            PRIMARY KEY(folder_id, message_id),
            FOREIGN KEY(folder_id) REFERENCES folders(folder_id),
            FOREIGN KEY(message_id) REFERENCES messages(message_id)
        );

        -- Source-side snapshot: every (folder, UIDVALIDITY, UID) already
        -- processed, so it is never downloaded again.
        --   imported   first copy of a message; file written
        --   linked     byte-identical to a message already stored
        --   suppressed matches a local-deletion tombstone; nothing stored
        CREATE TABLE imap_sources (
            folder_id INTEGER NOT NULL,
            uidvalidity TEXT NOT NULL,
            uid INTEGER NOT NULL,
            message_id INTEGER,
            status TEXT NOT NULL CHECK(status IN ('imported','linked','suppressed')),
            server_flags TEXT,
            first_seen_at TEXT NOT NULL,
            PRIMARY KEY(folder_id, uidvalidity, uid),
            FOREIGN KEY(folder_id) REFERENCES folders(folder_id),
            FOREIGN KEY(message_id) REFERENCES messages(message_id)
        );

        CREATE TABLE deleted_messages (
            sha256 TEXT PRIMARY KEY,
            deleted_at TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT 'local deletion'
        );

        CREATE INDEX idx_folder_messages_message ON folder_messages(message_id);
        CREATE INDEX idx_messages_shard ON messages(shard_id);
        CREATE INDEX idx_messages_rfc822 ON messages(rfc822_message_id);
        CREATE INDEX idx_imap_sources_message ON imap_sources(message_id);
        """
    )
    for key, value in (
        ("username", config["username"]),
        ("host", config["host"]),
        ("schema_version", str(SCHEMA_VERSION)),
    ):
        connection.execute(
            "INSERT INTO repository_info(key, value) VALUES (?, ?)", (key, value)
        )
    connection.commit()


def ensure_repository(connection: sqlite3.Connection, repository_path: Path,
                      config: dict, mode: str) -> None:
    if mode == "initial":
        repository_path.mkdir(parents=True, exist_ok=True)
        (repository_path / "messages").mkdir(exist_ok=True)
        create_schema(connection, config)
        write_repository_marker(repository_path, config)
        logging.info("Created new repository at %s", repository_path)
        return

    info = {
        row["key"]: row["value"]
        for row in connection.execute("SELECT key, value FROM repository_info")
    }
    if (info.get("username", "").casefold() != config["username"].casefold()
            or info.get("host", "").casefold() != config["host"].casefold()):
        raise RuntimeError(
            "The repository belongs to "
            f"{info.get('username')!r} on {info.get('host')!r}, not the configured "
            f"{config['username']!r} on {config['host']!r}. Set IMAP_REPOSITORY_NAME "
            "to use a separate repository directory."
        )

    required_tables = {
        "repository_info", "folders", "messages", "message_shards",
        "folder_messages", "imap_sources", "deleted_messages",
    }
    found = {
        row["name"]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    missing = required_tables - found
    if missing:
        raise RuntimeError(
            "Repository database is incomplete; missing tables: " + ", ".join(sorted(missing))
        )
    if int(info.get("schema_version", 0)) != SCHEMA_VERSION:
        raise RuntimeError(f"No migration path from repository schema {info.get('schema_version')}.")


def get_or_create_folder(connection: sqlite3.Connection, folder: dict) -> int:
    now = datetime.now(timezone.utc).isoformat()
    with transaction(connection):
        connection.execute(
            """
            INSERT INTO folders(name, imap_name, delimiter, last_seen_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                imap_name = excluded.imap_name,
                delimiter = excluded.delimiter,
                last_seen_at = excluded.last_seen_at
            """,
            (folder["name"], folder["imap_name"], folder["delimiter"], now),
        )
        row = connection.execute(
            "SELECT folder_id FROM folders WHERE name = ?", (folder["name"],)
        ).fetchone()
    return int(row["folder_id"])


def get_or_create_shard(connection: sqlite3.Connection,
                        repository_path: Path) -> tuple[int, str]:
    row = connection.execute(
        """
        SELECT shard_id, directory_name FROM message_shards
        WHERE file_count < ? ORDER BY shard_id DESC LIMIT 1
        """,
        (MAX_FILES_PER_SHARD,),
    ).fetchone()
    if row is None:
        with transaction(connection):
            cursor = connection.execute(
                "INSERT INTO message_shards(directory_name, file_count, created_at) VALUES ('', 0, ?)",
                (datetime.now(timezone.utc).isoformat(),),
            )
            shard_id = int(cursor.lastrowid)
            directory_name = f"{shard_id:06d}"
            connection.execute(
                "UPDATE message_shards SET directory_name = ? WHERE shard_id = ?",
                (directory_name, shard_id),
            )
        row = {"shard_id": shard_id, "directory_name": directory_name}
    shard_id = int(row["shard_id"])
    directory_name = str(row["directory_name"])
    (repository_path / "messages" / directory_name).mkdir(parents=True, exist_ok=True)
    return shard_id, directory_name


def extract_rfc822_message_id(raw: bytes) -> Optional[str]:
    try:
        headers = email.parser.BytesHeaderParser().parsebytes(raw)
        value = headers.get("Message-ID")
        return str(value).strip()[:998] if value else None
    except Exception:
        return None


def store_message(connection: sqlite3.Connection, repository_path: Path,
                  folder_id: int, uidvalidity: str, uid: int, fetched: dict,
                  resighting: bool) -> str:
    """Record one fetched message. Returns 'imported', 'linked' or 'suppressed'.

    resighting is True when the folder's UIDVALIDITY changed since earlier
    imports. Every UID is then new to us, but the messages are not new, so
    already-stored messages are linked without touching local folder
    membership (which the user may have reorganised).
    """
    raw = fetched["raw"]
    digest = hashlib.sha256(raw).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    flags = fetched.get("flags", set())
    flags_text = " ".join(sorted(flags))

    if connection.execute(
        "SELECT 1 FROM deleted_messages WHERE sha256 = ?", (digest,)
    ).fetchone():
        with transaction(connection):
            connection.execute(
                """
                INSERT INTO imap_sources(folder_id, uidvalidity, uid, message_id,
                                         status, server_flags, first_seen_at)
                VALUES (?, ?, ?, NULL, 'suppressed', ?, ?)
                """,
                (folder_id, uidvalidity, uid, flags_text, now),
            )
        return "suppressed"

    existing = connection.execute(
        "SELECT message_id FROM messages WHERE sha256 = ?", (digest,)
    ).fetchone()
    if existing:
        message_id = int(existing["message_id"])
        with transaction(connection):
            connection.execute(
                """
                INSERT INTO imap_sources(folder_id, uidvalidity, uid, message_id,
                                         status, server_flags, first_seen_at)
                VALUES (?, ?, ?, ?, 'linked', ?, ?)
                """,
                (folder_id, uidvalidity, uid, message_id, flags_text, now),
            )
            if not resighting:
                connection.execute(
                    "INSERT OR IGNORE INTO folder_messages(folder_id, message_id, first_seen_at) "
                    "VALUES (?, ?, ?)",
                    (folder_id, message_id, now),
                )
        return "linked"

    shard_id, directory_name = get_or_create_shard(connection, repository_path)
    filename = f"{digest}.eml"
    shard_path = repository_path / "messages" / directory_name
    final_path = shard_path / filename
    if final_path.exists():
        raise RuntimeError(f"Refusing to overwrite unexpected existing message file: {final_path}")

    check_disk_space(repository_path)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{digest[:16]}.", suffix=".tmp", dir=shard_path)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, final_path)
        try:
            with transaction(connection):
                cursor = connection.execute(
                    """
                    INSERT INTO messages(sha256, rfc822_message_id, shard_id, filename,
                                         message_size, internal_date, imported_at,
                                         is_read, is_starred)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        digest, extract_rfc822_message_id(raw), shard_id, filename,
                        len(raw), fetched.get("internal_date"), now,
                        int("\\seen" in flags), int("\\flagged" in flags),
                    ),
                )
                message_id = int(cursor.lastrowid)
                connection.execute(
                    """
                    INSERT INTO imap_sources(folder_id, uidvalidity, uid, message_id,
                                             status, server_flags, first_seen_at)
                    VALUES (?, ?, ?, ?, 'imported', ?, ?)
                    """,
                    (folder_id, uidvalidity, uid, message_id, flags_text, now),
                )
                connection.execute(
                    "INSERT INTO folder_messages(folder_id, message_id, first_seen_at) "
                    "VALUES (?, ?, ?)",
                    (folder_id, message_id, now),
                )
                connection.execute(
                    "UPDATE message_shards SET file_count = file_count + 1 WHERE shard_id = ?",
                    (shard_id,),
                )
        except BaseException:
            final_path.unlink(missing_ok=True)
            raise
    except BaseException as exc:
        temporary_path.unlink(missing_ok=True)
        if is_disk_full_error(exc):
            raise DiskSpaceExhausted(
                "The filesystem ran out of space while saving a message or updating "
                "SQLite. The current message was not committed; completed earlier "
                "messages remain in the repository. Free space and run the importer "
                "again to resume."
            ) from exc
        raise
    return "imported"


# --------------------------------------------------------------------------
# Synchronisation
# --------------------------------------------------------------------------

class Stats:
    def __init__(self):
        self.checked = 0
        self.imported = 0
        self.linked = 0
        self.suppressed = 0
        self.vanished = 0
        self.failed = 0


def _progress(label: str, done: int, total: int, stats: Stats, final: bool = False) -> None:
    line = (
        f"{label[:40]}: {done:,}/{total:,} | imported {stats.imported:,} | "
        f"linked {stats.linked:,} | failed {stats.failed:,}"
    )
    sys.stdout.write("\r" + line.ljust(110))
    if final:
        sys.stdout.write("\n")
    sys.stdout.flush()


def sync_folder(connection: sqlite3.Connection, session: ImapSession,
                repository_path: Path, folder: dict, stats: Stats) -> None:
    folder_id = get_or_create_folder(connection, folder)
    exists, uidvalidity = session.select_folder(folder["imap_name"])

    prior_epochs = {
        row[0] for row in connection.execute(
            "SELECT DISTINCT uidvalidity FROM imap_sources WHERE folder_id = ?", (folder_id,)
        )
    }
    resighting = bool(prior_epochs) and uidvalidity not in prior_epochs
    if resighting:
        logging.warning(
            "Folder %r has a new UIDVALIDITY (%s; previously %s). The server has "
            "renumbered it, so every message will be re-checked. Messages already "
            "stored are matched by content and will not be added to local folders again.",
            folder["name"], uidvalidity, ", ".join(sorted(prior_epochs)),
        )

    with transaction(connection):
        connection.execute(
            "UPDATE folders SET uidvalidity = ?, last_seen_at = ? WHERE folder_id = ?",
            (uidvalidity, datetime.now(timezone.utc).isoformat(), folder_id),
        )

    server_uids = session.search_all_uids()
    known = {
        row[0] for row in connection.execute(
            "SELECT uid FROM imap_sources WHERE folder_id = ? AND uidvalidity = ?",
            (folder_id, uidvalidity),
        )
    }
    new_uids = [uid for uid in server_uids if uid not in known]
    stats.checked += len(server_uids)
    logging.info(
        "Folder %r: %s on server, %s already processed, %s to fetch.",
        folder["name"], f"{len(server_uids):,}", f"{len(known):,}", f"{len(new_uids):,}",
    )

    done = 0
    try:
        for uid in new_uids:
            check_disk_space(repository_path)
            try:
                fetched = session.fetch_message(uid)
                if fetched is None or not fetched["raw"]:
                    # Expunged between SEARCH and FETCH, or an empty body.
                    stats.vanished += 1
                else:
                    outcome = store_message(
                        connection, repository_path, folder_id, uidvalidity,
                        uid, fetched, resighting,
                    )
                    if outcome == "imported":
                        stats.imported += 1
                    elif outcome == "linked":
                        stats.linked += 1
                    else:
                        stats.suppressed += 1
            except (DiskSpaceExhausted, ImapRetryExhausted, ImapAuthError):
                raise
            except ImapCommandError as exc:
                stats.failed += 1
                logging.error("Folder %r UID %s: %s", folder["name"], uid, exc)
            except Exception as exc:
                if is_disk_full_error(exc):
                    raise DiskSpaceExhausted(
                        "The filesystem ran out of space during import. The current "
                        "message was not committed; earlier completed messages remain "
                        "available. Free space and rerun to resume."
                    ) from exc
                stats.failed += 1
                if isinstance(exc, (RuntimeError, imaplib.IMAP4.error)):
                    logging.error("Folder %r UID %s failed: %s", folder["name"], uid, exc)
                else:
                    logging.exception("Failed importing folder %r UID %s", folder["name"], uid)
            done += 1
            if done % 10 == 0:
                _progress(folder["name"], done, len(new_uids), stats)
    finally:
        if new_uids:
            _progress(folder["name"], done, len(new_uids), stats, final=True)

    with transaction(connection):
        connection.execute(
            "UPDATE folders SET last_synced_at = ? WHERE folder_id = ?",
            (datetime.now(timezone.utc).isoformat(), folder_id),
        )


def sync_imap(connection: sqlite3.Connection, session: ImapSession,
              repository_path: Path, folders: list[dict]) -> Stats:
    stats = Stats()
    for folder in folders:
        try:
            sync_folder(connection, session, repository_path, folder, stats)
        except (DiskSpaceExhausted, ImapRetryExhausted, ImapAuthError):
            raise
        except ImapCommandError as exc:
            # Folder-level problem (cannot open, no UIDVALIDITY, UIDVALIDITY
            # changed mid-run). Other folders can still be imported.
            stats.failed += 1
            logging.error("Skipping folder %r: %s", folder["name"], exc)
    logging.info(
        "Completed scan: %s message(s) on server across %s folder(s); newly stored %s; "
        "linked to existing %s; suppressed by tombstone %s; vanished %s; failures %s",
        f"{stats.checked:,}", len(folders), f"{stats.imported:,}", f"{stats.linked:,}",
        f"{stats.suppressed:,}", f"{stats.vanished:,}", f"{stats.failed:,}",
    )
    return stats


# --------------------------------------------------------------------------
# Local deletion and integrity checking
# --------------------------------------------------------------------------

def delete_local_message(connection: sqlite3.Connection, repository_path: Path,
                         sha256: str, reason: str = "local deletion") -> bool:
    """Permanently remove one active message and create a content tombstone.

    Not wired to the command line (as in the Gmail importer); available for a
    future local mail client. Offline backup copies are unaffected.
    """
    tombstone_sql = """
        INSERT INTO deleted_messages(sha256, deleted_at, reason) VALUES (?, ?, ?)
        ON CONFLICT(sha256) DO UPDATE SET
            deleted_at = excluded.deleted_at, reason = excluded.reason
    """
    now = datetime.now(timezone.utc).isoformat()
    row = connection.execute(
        """
        SELECT m.message_id, m.shard_id, m.filename, s.directory_name
        FROM messages m JOIN message_shards s ON s.shard_id = m.shard_id
        WHERE m.sha256 = ?
        """,
        (sha256,),
    ).fetchone()
    if row is None:
        with transaction(connection):
            connection.execute(tombstone_sql, (sha256, now, reason))
        return False

    original_path = repository_path / "messages" / row["directory_name"] / row["filename"]
    if not original_path.is_file():
        raise RuntimeError(f"Cannot delete {sha256}: its repository file is missing: {original_path}")
    quarantine_path = original_path.with_name(original_path.name + ".deleting")
    if quarantine_path.exists():
        raise RuntimeError(f"Deletion recovery file already exists: {quarantine_path}")
    os.replace(original_path, quarantine_path)
    try:
        with transaction(connection):
            message_id = int(row["message_id"])
            connection.execute(tombstone_sql, (sha256, now, reason))
            connection.execute("DELETE FROM folder_messages WHERE message_id = ?", (message_id,))
            connection.execute(
                "UPDATE imap_sources SET message_id = NULL, status = 'suppressed' "
                "WHERE message_id = ?", (message_id,),
            )
            connection.execute("DELETE FROM messages WHERE message_id = ?", (message_id,))
            connection.execute(
                "UPDATE message_shards SET file_count = file_count - 1 "
                "WHERE shard_id = ? AND file_count > 0", (int(row["shard_id"]),),
            )
    except Exception:
        os.replace(quarantine_path, original_path)
        raise
    quarantine_path.unlink(missing_ok=True)
    return True


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_repository_files(connection: sqlite3.Connection, repository_path: Path) -> None:
    """Check DB/file consistency; never silently delete or rewrite files."""
    missing = []
    known_paths = set()
    for row in connection.execute(
        """
        SELECT m.sha256, s.directory_name, m.filename, m.message_size
        FROM messages m JOIN message_shards s ON s.shard_id = m.shard_id
        """
    ):
        path = repository_path / "messages" / row["directory_name"] / row["filename"]
        known_paths.add((row["directory_name"], row["filename"]))
        if not path.is_file():
            missing.append((row["sha256"], str(path)))
            continue
        if path.stat().st_size != int(row["message_size"]):
            raise RuntimeError(
                f"Repository integrity check found a size mismatch for {row['sha256']}: {path}"
            )
        if sha256_file(path) != row["sha256"]:
            raise RuntimeError(
                f"Repository integrity check found a SHA-256 mismatch for {row['sha256']}: {path}"
            )
    if missing:
        examples = "\n".join(f"  {digest}: {path}" for digest, path in missing[:10])
        raise RuntimeError(
            f"Repository integrity check found {len(missing)} missing message file(s). "
            f"No sync was started. Examples:\n{examples}"
        )

    orphaned = []
    for shard_dir in (repository_path / "messages").iterdir():
        if not shard_dir.is_dir():
            orphaned.append(str(shard_dir))
            continue
        for item in shard_dir.iterdir():
            if item.name.endswith(".eml") and (shard_dir.name, item.name) not in known_paths:
                orphaned.append(str(item))
            elif item.name.endswith((".deleting", ".tmp")):
                orphaned.append(str(item))
    if orphaned:
        raise RuntimeError(
            "Repository integrity check found untracked or interrupted message files. "
            "No sync was started. Inspect these paths before proceeding:\n  "
            + "\n  ".join(orphaned[:20])
        )

    with transaction(connection):
        for row in connection.execute(
            """
            SELECT s.shard_id, COUNT(m.message_id) AS actual_count
            FROM message_shards s LEFT JOIN messages m ON m.shard_id = s.shard_id
            GROUP BY s.shard_id
            """
        ).fetchall():
            actual = int(row["actual_count"])
            if actual > MAX_FILES_PER_SHARD:
                raise RuntimeError(
                    f"Shard {row['shard_id']} contains {actual} records; "
                    f"the limit is {MAX_FILES_PER_SHARD}."
                )
            connection.execute(
                "UPDATE message_shards SET file_count = ? WHERE shard_id = ?",
                (actual, int(row["shard_id"])),
            )


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def build_argument_parser() -> argparse.ArgumentParser:
    prog = Path(sys.argv[0]).name
    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Import messages from any IMAP4 server into an authoritative local "
            "repository. All settings come from environment variables."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
A. REGULAR IMAP (username + password; any IMAP4 server) -- the default
  IMAP_HOST                 IMAP server host name
  IMAP_USERNAME             Login name (often the full e-mail address)
  IMAP_PASSWORD_FILE        File containing the password (preferred; chmod 600)
  IMAP_PASSWORD             Password in the environment (alternative)

B. OUTLOOK.COM OAUTH (Microsoft personal accounts ONLY; IMAP_AUTH=microsoft-oauth2)
  Not for Gmail, Yahoo or other providers. Use A for those.
  IMAP_USERNAME             The Outlook.com address
  IMAP_OAUTH_CLIENT_ID      Application (client) ID of your Microsoft Entra app
  IMAP_HOST                 Default outlook.office365.com
  IMAP_OAUTH_TOKEN_FILE     Saved sign-in (default ~/.config/imap-local-repository/
                            <username>.oauth.json, owner-only)
  IMAP_OAUTH_TENANT         Default consumers (personal Microsoft accounts)
  IMAP_OAUTH_SCOPES         Default https://outlook.office.com/IMAP.AccessAsUser.All offline_access
  Run once with --authorise: it shows a code and URL; open the URL on any
  device with a browser, enter the code and sign in. No browser is needed on
  the machine running this script.

OPTIONAL SETTINGS (both)
  IMAP_SECURITY             ssl (default; implicit TLS, port 993) or starttls (port 143).
                            Unencrypted IMAP is not supported.
  IMAP_PORT                 Override the default port
  IMAP_CA_FILE              PEM file with a private CA for servers whose
                            certificate is not publicly trusted
  IMAP_FOLDERS              Comma-separated folders to import (default: all
                            selectable folders). A trailing * matches a prefix.
  IMAP_EXCLUDE_FOLDERS      Comma-separated folders to skip (same syntax)
  IMAP_REPOSITORY_NAME      Repository directory name (default: the username)
  IMAP_REQUEST_INTERVAL     Minimum seconds between commands (default 0; raised
                            automatically if the server throttles)
  IMAP_IPV4_ONLY            auto (default: use IPv4 only if IPv6 does not work),
                            true or false
  IMAP_MIN_FREE_BYTES       Free-space reserve (default {DEFAULT_MIN_FREE_BYTES}; 0 disables)
  DB_LOCATION               Parent directory for repositories (default {DEFAULT_DB_LOCATION})

EXAMPLE
  export IMAP_HOST="imap.example.com"
  export IMAP_USERNAME="you@example.com"
  export IMAP_PASSWORD_FILE="$HOME/.config/imap-local-repository/password"
  export DB_LOCATION="$HOME/mail-data"
  {prog}

The repository is created at DB_LOCATION/<encoded-name>/ and contains
{DATABASE_FILENAME}, {REPOSITORY_MARKER} and a messages/ directory with shards of
at most {MAX_FILES_PER_SHARD} .eml files.

BEHAVIOUR
  - The server is only read: folders are opened with EXAMINE and bodies are
    fetched with BODY.PEEK[], so no flags change.
  - Each distinct message (by SHA-256 of its bytes) is stored once, however
    many server folders hold a copy.
  - Server deletions, moves and flag changes never delete local data.
  - Local deletion tombstones suppress re-import.
  - Dropped connections are re-established; throttling is met with backoff.

EXIT CODES
  0 ok   1 some messages/folders failed   2 configuration/auth/repository error
  3 server kept failing after retries     4 disk full   130 Ctrl-C
""",
    )
    parser.add_argument(
        "--authorise", "--authorize", dest="authorise", action="store_true",
        help="Outlook.com only: sign in once (device-code flow) and save the token",
    )
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()  # --help works without any environment

    connection = None
    session = None
    try:
        config = get_configuration()
        apply_network_preference(config)
        if args.authorise:
            return run_authorise(config)
        repository_path = config["repository_path"]
        mode = detect_repository_mode(repository_path)

        # Log in and list folders before creating a new repository, so a failed
        # setup never leaves a half-created repository behind.
        session = ImapSession(config)
        session.call("login", lambda c: ("OK", []))
        all_folders = session.list_folders()
        folders = choose_folders(all_folders, config["include_folders"], config["exclude_folders"])
        if not folders:
            raise RuntimeError("No selectable folders to import after applying IMAP_FOLDERS / IMAP_EXCLUDE_FOLDERS.")
        logging.info(
            "Server has %s folder(s); importing %s: %s",
            len(all_folders), len(folders), ", ".join(f["name"] for f in folders),
        )

        repository_path.mkdir(parents=True, exist_ok=True)
        connection = connect_database(config["database_path"])
        ensure_repository(connection, repository_path, config, mode)
        if mode == "sync":
            verify_repository_files(connection, repository_path)

        logging.info("Import mode: %s", "initial import" if mode == "initial" else "incremental sync")
        logging.info("Repository: %s", repository_path)

        check_disk_space(repository_path)
        stats = sync_imap(connection, session, repository_path, folders)
        logging.info(
            "Finished: newly stored %s message(s); failed %s.",
            f"{stats.imported:,}", f"{stats.failed:,}",
        )
        return 1 if stats.failed else 0

    except KeyboardInterrupt:
        logging.warning(
            "Interrupted by user (Ctrl-C). The importer is stopping; completed "
            "messages remain saved and the next run can resume."
        )
        return 130
    except ImapRetryExhausted as exc:
        logging.error("%s", exc)
        return 3
    except DiskSpaceExhausted as exc:
        logging.error("DISK SPACE: %s", exc)
        return 4
    except ImapAuthError as exc:
        logging.error("%s", exc)
        return 2
    except (ValueError, RuntimeError, OSError, sqlite3.Error, imaplib.IMAP4.error) as exc:
        if is_disk_full_error(exc):
            logging.error(
                "DISK SPACE: the filesystem could not complete a write. The importer "
                "has stopped. Free space and run it again to resume."
            )
            return 4
        logging.error("%s", exc)
        return 2
    except Exception as exc:
        logging.error("Importer failure (%s): %s", type(exc).__name__, exc)
        return 2
    finally:
        if session is not None:
            session.close()
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    raise SystemExit(main())
