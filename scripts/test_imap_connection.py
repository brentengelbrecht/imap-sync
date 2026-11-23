#!/usr/bin/env python3
"""Headless IMAP connection test. Reads nothing but folder status.

Uses the same environment variables as imap_local_repository.py
(IMAP_HOST, IMAP_USERNAME, IMAP_PASSWORD_FILE or IMAP_PASSWORD, and optionally
IMAP_SECURITY, IMAP_PORT, IMAP_CA_FILE). With IMAP_AUTH=oauth2 it uses the saved
OAuth sign-in (see --authorise in imap_local_repository.py). Lists every folder with its message
count and shows the name to use in IMAP_FOLDERS / IMAP_EXCLUDE_FOLDERS.
No messages are fetched, changed, or deleted.
"""
import sys
import imap_local_repository as imp


def main() -> int:
    try:
        config = imp.get_configuration()
        imp.apply_network_preference(config)
        session = imp.ImapSession(config)
        session.call("login", lambda c: ("OK", []))
        folders = session.list_folders()
        print(f"SUCCESS: logged in to {config['host']}:{config['port']} as {config['username']}")
        print(f"Folders ({len(folders)}):")
        total = 0
        for f in folders:
            if "\\noselect" in f["flags"] or "\\nonexistent" in f["flags"]:
                print(f"  {f['name']}  (not selectable)")
                continue
            exists, _ = session.select_folder(f["imap_name"])
            total += exists
            print(f"  {f['name']}  [{exists:,} messages]")
        print(f"Total across folders: {total:,} (a message in several folders is counted in each)")
        print("Folders were opened read-only. No messages were retrieved, changed, or deleted.")
        session.close()
        return 0
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
