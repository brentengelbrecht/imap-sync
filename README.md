# IMAP Local Repository Importer

A one-way importer from an IMAP4 server into a local repository (SQLite + sharded `.eml` files). It is the IMAP counterpart of the Gmail API importer: same repository model, integrity checks, tombstones and exit codes, and it runs headless.

## 1. Choose your login type

There are two ways to log in. They are separate code paths with separate settings; pick one.

| | **A. Regular IMAP** | **B. Outlook.com OAuth** |
|---|---|---|
| Works with | Any IMAP4 server that accepts a password | **Personal Microsoft accounts only** (outlook.com, hotmail.com, live.com) |
| `IMAP_AUTH` | `password` (the default) | `microsoft-oauth2` |
| Login | Username + password (an app password where the provider offers one) | Sign in once in a browser on any device; the importer then renews its own tokens |
| One-time setup | None | Register an app in Microsoft Entra, then run `--authorise` once |
| Secret on disk | Password file | OAuth token file |
| Section | [3](#3-regular-imap-password-login) | [4](#4-outlookcom-with-oauth) |

**The OAuth support is Microsoft-specific.** It uses Microsoft's sign-in endpoints, a Microsoft Entra app registration, Microsoft's IMAP scope and the `consumers` tenant. It does **not** work for Gmail, Yahoo or any other provider's OAuth, even though several providers use the same XOAUTH2 login step. Supporting another provider would need its own sign-in endpoints, scopes and app registration. For Gmail, use an app password with option A, or the Gmail API importer.

Work/school Microsoft 365 accounts are **not** supported by either option.

## 2. What it does (both login types)

- Creates a local repository on the first run and imports only previously unseen messages on later runs.
- Imports every selectable folder, or the ones you choose.
- Stores each message as its raw RFC 822 bytes in `.eml` files, in shards of at most 500.
- Stores a message **once** even if the server holds copies in several folders; it is identified by the SHA-256 of its bytes. Local folder memberships record where it was found.
- Never writes to the server. Folders are opened with `EXAMINE` and bodies fetched with `BODY.PEEK[]`, so `\Seen` is not set.
- Never deletes local data because something changed on the server.
- Reconnects after dropped connections and backs off when the server throttles.
- Switches to IPv4 automatically when IPv6 does not work on your network.
- Checks file integrity (size + SHA-256) before every incremental sync.

**Requirements:** Python 3.9 or later, standard library only (no packages to install), and network access to the server (TLS required).

---

## 3. Regular IMAP (password login)

Use this for any provider that accepts a username and password over IMAP: Fastmail, iCloud, Gmail (with an app password), Dovecot/Postfix servers, most ISPs.

### Setup

```bash
mkdir -p "$HOME/.config/imap-local-repository"
chmod 700 "$HOME/.config/imap-local-repository"
printf '%s' 'your-app-password' > "$HOME/.config/imap-local-repository/password"
chmod 600 "$HOME/.config/imap-local-repository/password"

export IMAP_HOST="imap.example.com"
export IMAP_USERNAME="you@example.com"
export IMAP_PASSWORD_FILE="$HOME/.config/imap-local-repository/password"
export DB_LOCATION="$HOME/mail-data"

python test_imap_connection.py      # optional: login + folder list, nothing downloaded
python imap_local_repository.py
```

Prefer `IMAP_PASSWORD_FILE` over `IMAP_PASSWORD`: environment variables can leak through process listings and shell history. Do not use the variable name `USERNAME`; on Windows it already holds the OS user name.

### Settings specific to regular IMAP

| Variable | Required | Description |
|---|---:|---|
| `IMAP_HOST` | Yes | Server host name |
| `IMAP_USERNAME` | Yes | Login name |
| `IMAP_PASSWORD_FILE` | One of the two | File containing the password (trailing newline removed) |
| `IMAP_PASSWORD` | One of the two | Password directly |

### Provider notes

Provider policies change; check your provider's current documentation.

- **Gmail over IMAP:** needs IMAP enabled and normally an app password (2-Step Verification on). Folders include `[Gmail]/All Mail`, which duplicates the other folders' contents; set `IMAP_EXCLUDE_FOLDERS` or `IMAP_FOLDERS` to avoid downloading everything twice. For Gmail, the API importer remains the better tool.
- **Outlook.com / Hotmail:** password login no longer works. Use option B.
- **Microsoft 365 work/school:** not supported.

---

## 4. Outlook.com with OAuth

For **personal Microsoft accounts only**. Set `IMAP_AUTH=microsoft-oauth2`. Nothing in this section applies to option A, and the password settings are ignored in this mode.

The importer machine needs no browser: sign-in uses the device-code flow, where you open a URL and enter a code on any other device (phone, laptop).

### One-time Microsoft setup (Microsoft Entra admin centre, App registrations)

1. New registration. Supported account types must include **personal Microsoft accounts**.
2. Authentication: set **Allow public client flows** to **Yes**.
3. API permissions: add the delegated permissions `IMAP.AccessAsUser.All` and `offline_access`.
4. Copy the **Application (client) ID**. No client secret is used.

### Settings specific to Outlook.com OAuth

| Variable | Required | Description |
|---|---:|---|
| `IMAP_AUTH` | Yes | Must be `microsoft-oauth2`. (The old value `oauth2` is refused with a hint.) |
| `IMAP_USERNAME` | Yes | The Outlook.com address |
| `IMAP_OAUTH_CLIENT_ID` | Yes | Application (client) ID from step 4 |
| `IMAP_HOST` | No | Default `outlook.office365.com` |
| `IMAP_OAUTH_TOKEN_FILE` | No | Saved sign-in. Default `~/.config/imap-local-repository/<username>.oauth.json` (owner-only) |
| `IMAP_OAUTH_TENANT` | No | Default `consumers` (personal Microsoft accounts) |
| `IMAP_OAUTH_SCOPES` | No | Default `https://outlook.office.com/IMAP.AccessAsUser.All offline_access` |

### Sign in once, then import

```bash
export IMAP_AUTH=microsoft-oauth2
export IMAP_USERNAME="you@outlook.com"
export IMAP_OAUTH_CLIENT_ID="<application-client-id>"
export DB_LOCATION="$HOME/mail-data"

python imap_local_repository.py --authorise   # once
python imap_local_repository.py               # every run after that
```

`--authorise` prints a code and a URL. Open the URL on any device with a browser, enter the code and sign in as the Outlook.com account. The importer then checks that this account can log in over IMAP and **only then** saves the token (owner-only file). Nothing is saved if the check fails, for example when you signed in with a different account.

### Keeping it working

- Each run renews the access token itself and saves the rotated refresh token. If the server rejects a cached token, a fresh one is fetched and the run carries on. Brief 503 errors from Microsoft's token endpoint are retried with backoff.
- Run the importer regularly (cron or a systemd timer). A refresh token that is never used eventually expires, as does one invalidated by a password change. The importer then exits with code 2 and tells you to run `--authorise` again.
- The token file is a credential: anyone with it can read the mailbox. Keep it `chmod 600` and out of backups you do not trust.
- `test_outlook_oauth.py` is a standalone diagnostic for this option only. It tries three scope variants against Outlook.com and reports which authenticates. Delete its saved token with `--forget` when you are done.

### Troubleshooting (Outlook.com OAuth)

- **Exit 2 saying to run `--authorise`:** the saved sign-in was revoked or expired; run `--authorise` again.
- **`--authorise` says the server rejected the new sign-in:** sign in as the same address as `IMAP_USERNAME`, and check the app has `IMAP.AccessAsUser.All` and public client flows enabled.
- **Could not start the sign-in:** check `IMAP_OAUTH_CLIENT_ID` and that public client flows are enabled.
- **Long silent stalls:** broken IPv6. The importer detects this and switches to IPv4; force it with `IMAP_IPV4_ONLY=true`.

---

## 5. Settings for both login types

| Variable | Description |
|---|---|
| `IMAP_SECURITY` | `ssl` (default, implicit TLS, port 993) or `starttls` (port 143). Unencrypted IMAP is refused. |
| `IMAP_PORT` | Override the port |
| `IMAP_CA_FILE` | PEM file for a private certificate authority. Certificates are always verified. |
| `IMAP_FOLDERS` | Comma-separated folders to import; trailing `*` matches a prefix. Default: all selectable folders. |
| `IMAP_EXCLUDE_FOLDERS` | Comma-separated folders to skip (same syntax) |
| `IMAP_REPOSITORY_NAME` | Repository directory name (default: the username) |
| `IMAP_REQUEST_INTERVAL` | Minimum seconds between commands (default 0). Raised automatically if the server throttles. |
| `IMAP_IPV4_ONLY` | `auto` (default: IPv4 only when IPv6 is unusable), `true` or `false` |
| `IMAP_MIN_FREE_BYTES` | Free-space reserve, default 64 MiB; `0` disables |
| `DB_LOCATION` | Parent directory for repositories, default `./data` |

Folder names are matched case-insensitively against the decoded names shown by `test_imap_connection.py` (for example `Entwürfe`, not the on-the-wire `Entw&APw-rfe`). Example: `IMAP_EXCLUDE_FOLDERS="[Gmail]/All Mail,Junk*"`.

## 6. Repository layout

```text
DB_LOCATION/<URL-encoded name>/
    repository.json
    repository.db
    messages/<shard>/<sha256>.eml
```

- A missing or empty directory starts an initial import; a recognised repository starts an incremental sync; any other non-empty directory is rejected.
- A repository is tied to one host + username. Using it with a different account stops with an error; use `IMAP_REPOSITORY_NAME` to keep separate repositories.
- Both login types write the same repository format, and the archive server reads them the same way.

## 7. Behaviour worth knowing

- **Duplicates:** the same bytes in several folders are detected **after download**, so each copy is downloaded once per folder, then stored once.
- **Local folder membership is additive.** A message found in a folder gets membership there; later server-side moves add the new folder but never remove the old one. If you reorganise locally, the server's old UIDs are already recorded, so it is not put back.
- **UIDVALIDITY changes.** If a server renumbers a folder, every message is re-checked (and re-downloaded, since that is the only way to compare content), but already-stored messages are matched by hash and not duplicated or re-added to local folders. A warning is logged.
- **Failures are retried.** Only successfully processed UIDs are recorded, so a failed message is attempted again on the next run (and keeps the exit code at 1 while it keeps failing).
- **Messages that disappear mid-run** (expunged between listing and fetching) are skipped without counting as failures.
- **Flags:** `\Seen` and `\Flagged` set the local read/starred state when a message is first imported; later server flag changes are not mirrored.
- **Speed:** messages are fetched one at a time, which is simple and robust but slower than bulk fetching on high-latency links.

## 8. Troubleshooting (both login types)

- **Login rejected (regular IMAP):** check the username format (some servers want the full address), use an app password, and confirm IMAP is enabled for the account.
- **TLS certificate verification failed:** the server's certificate is not publicly trusted. Set `IMAP_CA_FILE` to the issuing CA's PEM file.
- **`does not offer STARTTLS`:** use `IMAP_SECURITY=ssl` with port 993, or a server that supports encryption.
- **Repeated "server asked to slow down" / "kept failing":** the server is limiting you. Set `IMAP_REQUEST_INTERVAL=1` and rerun later.
- **Integrity errors:** do not delete or rename files to silence them; inspect the named paths and restore from backup if necessary.

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | Completed without failures |
| `1` | Completed, but one or more messages or folders failed |
| `2` | Configuration, authentication, repository or non-retryable error |
| `3` | Server errors/throttling persisted after retries; rerun later |
| `4` | Disk full; free space and rerun |
| `130` | Interrupted with Ctrl-C; rerun to resume |

## 9. Differences from the Gmail API importer

| Topic | Gmail API importer | This importer |
|---|---|---|
| Message identity | Gmail message ID | SHA-256 of the raw message (IMAP UIDs are only unique within one folder and UIDVALIDITY epoch) |
| Folders | Gmail labels | IMAP folders |
| Authentication | Service account or OAuth (Google) | A: username + password. B: Outlook.com OAuth (Microsoft only) |
| Rate limiting | Adaptive Gmail quota pacing | Reconnect + exponential backoff; optional request interval |
| Repository marker | `gmail-local-repository` | `imap-local-repository`. The two repository types are not interchangeable. |

## 10. Operational cautions

- Do not run two importers against the same repository at once.
- Protect the password file or OAuth token file, and any backups: backups contain message contents.
- **Testing status:** the `tests/` directory runs the importer against an in-process fake IMAP server over TLS (initial import, duplicates across folders, UTF-7 folder names, a 3 MB message, dropped connection, UIDVALIDITY change, bad password, tombstone, tampered file), and the OAuth path against a mock Microsoft endpoint (device sign-in, token rotation, rejected token, revoked sign-in, flaky token endpoint, wrong account). Option B's sign-in and scope were confirmed on a real Outlook.com account with `test_outlook_oauth.py`, but the importer has not yet been run against a real provider's server; try a small folder first (`IMAP_FOLDERS=INBOX`).
