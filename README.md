# IMAP Local Repository Importer

A one-way importer from any IMAP4 server into a local repository. It is the generic-IMAP counterpart of the Gmail API importer: same repository model (SQLite + sharded `.eml` files, integrity checks, tombstones), same exit codes, same headless operation.

## 1. What it does

- Creates a local repository on the first run and imports only previously unseen messages on later runs.
- Imports every selectable folder (or the ones you choose).
- Stores each message as its raw RFC 822 bytes in `.eml` files, in shards of at most 500.
- Stores a message **once** even if the server holds copies in several folders; it is identified by the SHA-256 of its bytes. Local folder memberships record where it was found.
- Never writes to the server. Folders are opened with `EXAMINE` and bodies fetched with `BODY.PEEK[]`, so `\Seen` is not set.
- Never deletes local data because something changed on the server.
- Reconnects after dropped connections and backs off when the server throttles.
- Checks file integrity (size + SHA-256) before every incremental sync.

## 2. Differences from the Gmail importer

| Topic | Gmail API importer | IMAP importer |
|---|---|---|
| Message identity | Gmail message ID | SHA-256 of the raw message. IMAP UIDs are only unique within one folder and UIDVALIDITY epoch. |
| Duplicates | One Gmail message, many labels | Same bytes in several folders are detected **after download**, so each copy is downloaded once per folder, then stored once. |
| Folders | Gmail labels | IMAP folders |
| Re-fetch avoidance | Message ID known | `(folder, UIDVALIDITY, UID)` recorded for everything processed |
| Authentication | Service account or OAuth | Username + password (preferably an app password) |
| Rate limiting | Adaptive Gmail quota pacing | Reconnect + exponential backoff; optional request interval |
| Repository marker | `gmail-local-repository` | `imap-local-repository`. The two repository types are not interchangeable. |

**Local folder membership is additive.** A message found in a folder gets membership there; later server-side moves add the new folder but never remove the old one. If you reorganise locally, the server's old UIDs are already recorded, so it will not be put back.

## 3. Requirements

- Python 3.9 or later. **No third-party packages**: only the standard library.
- Network access to the IMAP server (TLS required).
- Enough disk space for the messages and the SQLite database.

## 4. Setup

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

Prefer `IMAP_PASSWORD_FILE` over `IMAP_PASSWORD`: environment variables can leak through process listings and shell history. Do not use the variable name `USERNAME`; on Windows it already holds the OS user name (the old `sync_imap.py` read it).

### Provider notes

These are general observations and provider policies change; check your provider's current documentation.

- **Gmail over IMAP:** needs IMAP enabled and normally an app password (2-Step Verification on). Folders include `[Gmail]/All Mail`, which duplicates the other folders' contents; set `IMAP_EXCLUDE_FOLDERS` or `IMAP_FOLDERS` to avoid downloading everything twice. For Gmail, the API importer remains the better tool.
- **Microsoft 365 / Outlook.com:** basic username+password IMAP is, as far as I know, disabled or being phased out; they need OAuth (XOAUTH2), which this version does not implement.
- **Most other hosts** (Fastmail, iCloud, Dovecot/Postfix servers, ISPs): username + app/regular password over port 993 works.

## 5. Configuration reference

| Variable | Required | Description |
|---|---:|---|
| `IMAP_HOST` | Yes | Server host name |
| `IMAP_USERNAME` | Yes | Login name |
| `IMAP_PASSWORD_FILE` | One of the two | File containing the password (trailing newline removed) |
| `IMAP_PASSWORD` | One of the two | Password directly |
| `IMAP_SECURITY` | No | `ssl` (default, implicit TLS, port 993) or `starttls` (port 143). Unencrypted IMAP is refused. |
| `IMAP_PORT` | No | Override the port |
| `IMAP_CA_FILE` | No | PEM file for a private certificate authority. Certificates are always verified. |
| `IMAP_FOLDERS` | No | Comma-separated folders to import; trailing `*` matches a prefix. Default: all selectable folders. |
| `IMAP_EXCLUDE_FOLDERS` | No | Comma-separated folders to skip (same syntax) |
| `IMAP_REPOSITORY_NAME` | No | Repository directory name (default: the username) |
| `IMAP_REQUEST_INTERVAL` | No | Minimum seconds between commands (default 0). Raised automatically if the server throttles. |
| `IMAP_MIN_FREE_BYTES` | No | Free-space reserve, default 64 MiB; `0` disables |
| `DB_LOCATION` | No | Parent directory for repositories, default `./data` |

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

## 7. Behaviour worth knowing

- **UIDVALIDITY changes.** If a server renumbers a folder, every message is re-checked (and re-downloaded, since that is the only way to compare content), but already-stored messages are matched by hash and not duplicated or re-added to local folders. A warning is logged.
- **Failures are retried.** Only successfully processed UIDs are recorded, so a message that failed is attempted again on the next run (and keeps the exit code at 1 while it keeps failing).
- **Messages that disappear mid-run** (expunged between listing and fetching) are skipped without counting as failures.
- **Flags:** `\Seen` and `\Flagged` set the local read/starred state when a message is first imported; later server flag changes are not mirrored.
- **Speed:** messages are fetched one at a time, which is simple and robust but slower than bulk fetching on high-latency links.

## 8. Troubleshooting

- **Login rejected:** check the username format (some servers want the full address), use an app password, and confirm IMAP is enabled for the account.
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

## 9. Operational cautions

- Do not run two importers against the same repository at once.
- Protect the password file and any backups: backups contain message contents.
- **Testing status:** `tests/run_fake_test.py` runs the importer against an in-process fake IMAP server over TLS (initial import, duplicates across folders, UTF-7 folder names, 3 MB message, dropped connection, UIDVALIDITY change, bad password, tombstone, tampered file). It has **not** been run against a real provider's server; try a small folder first.
