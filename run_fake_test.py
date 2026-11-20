import os, sys, subprocess, tempfile, sqlite3, hashlib, shutil
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent)); sys.path.insert(0, str(Path(__file__).parent.parent))
import logging; logging.basicConfig(level=logging.WARNING)
import imap_local_repository as imp
from fake_imap_server import FakeImapServer

tmp = Path(tempfile.mkdtemp())
cert, key = tmp/"c.pem", tmp/"k.pem"
subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,"-out",cert,"-days","2",
  "-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost,IP:127.0.0.1"],check=True,capture_output=True)

def msg(n, extra=b""):
    return (b"From: a@x\r\nTo: b@x\r\nSubject: m%d\r\nMessage-ID: <%d@x>\r\n\r\nbody %d\r\n" % (n,n,n)) + extra
big = msg(99, b"x"*3_000_000)
D = "17-Jul-2024 02:44:25 -0700"
srv = FakeImapServer(cert, key)
srv.folders = {
  "INBOX": {"uidvalidity": 11, "flags": [r"\HasNoChildren"], "msgs": {1:(r"\Seen",D,msg(1)), 2:(r"\Flagged",D,msg(2)), 5:("",D,big)}},
  "Archive": {"uidvalidity": 22, "flags": [], "msgs": {7:(r"\Seen",D,msg(1)), 8:("",D,msg(3))}},   # msg1 duplicate
  "Entw&APw-rfe": {"uidvalidity": 33, "flags": [], "msgs": {1:("",D,msg(4))}},
  "[Gmail]": {"uidvalidity": 1, "flags": [r"\Noselect"], "msgs": {}},
}
srv.start()
env = dict(IMAP_HOST="localhost", IMAP_PORT=str(srv.port), IMAP_USERNAME="u", IMAP_PASSWORD="p",
           IMAP_CA_FILE=str(cert), DB_LOCATION=str(tmp/"data"), IMAP_MIN_FREE_BYTES="0")
os.environ.update(env); imp.INITIAL_BACKOFF_SECONDS = 0.05
def db():
    c = sqlite3.connect(tmp/"data"/"u"/"repository.db"); c.row_factory = sqlite3.Row; return c
def check(c, label):
    print("OK  " if c else "FAIL", label); 
    if not c: sys.exit(1)

rc = imp.main(); check(rc == 0, f"initial import exit 0 (got {rc})")
c = db()
check(c.execute("select count(*) from messages").fetchone()[0] == 5, "5 distinct messages stored (6 on server, 1 duplicate)")
check(c.execute("select count(*) from imap_sources").fetchone()[0] == 6, "6 source rows")
check(c.execute("select count(*) from folder_messages").fetchone()[0] == 6, "6 folder memberships (dup in 2 folders)")
check(c.execute("select 1 from folders where name='Entwürfe'").fetchone(), "UTF-7 folder name decoded")
check(not c.execute("select 1 from folders where name='[Gmail]'").fetchone(), "\\Noselect folder skipped")
r = c.execute("select is_read,is_starred,internal_date from messages m join imap_sources s using(message_id) where uid=1 and folder_id=(select folder_id from folders where name='INBOX')").fetchone()
check(r["is_read"]==1 and r["is_starred"]==0 and r["internal_date"].startswith("2024-07-17T09:44:25"), f"flags + INTERNALDATE→UTC ({dict(r)})")
check(c.execute("select message_size from messages where message_size>3000000").fetchone(), "3 MB message stored intact")
c.close()

srv.fetch_log.clear(); rc = imp.main(); check(rc == 0 and not srv.fetch_log, "second run fetches nothing")

# new mail + a connection drop on first fetch
srv.folders["INBOX"]["msgs"][9] = ("", D, msg(9)); srv.folders["INBOX"]["msgs"][10] = ("", D, msg(10))
srv.fetch_count = 0; srv.drop_on_fetch = 1
rc = imp.main(); check(rc == 0, f"recovers from dropped connection (rc {rc})")
check(db().execute("select count(*) from messages").fetchone()[0] == 7, "2 new messages stored after reconnect")
srv.drop_on_fetch = None

# UIDVALIDITY change: same content renumbered
srv.folders["Archive"] = {"uidvalidity": 99, "flags": [], "msgs": {1:(r"\Seen",D,msg(1)), 2:("",D,msg(3))}}
rc = imp.main(); c = db()
check(rc == 0 and c.execute("select count(*) from messages").fetchone()[0] == 7, "UIDVALIDITY change: no duplicate messages")
check(c.execute("select count(*) from folder_messages").fetchone()[0] == 8, "memberships not re-added on resighting")

# bad password -> exit 2, no retry storm
os.environ["IMAP_PASSWORD"] = "wrong"; rc = imp.main(); check(rc == 2, f"bad password exit 2 (got {rc})")
os.environ["IMAP_PASSWORD"] = "p"

# tombstone suppresses re-import
c = db(); digest = hashlib.sha256(msg(9)).hexdigest()
imp.delete_local_message(c, tmp/"data"/"u", digest); c.execute("delete from imap_sources where uid=9"); c.commit(); c.close()
rc = imp.main(); c = db()
check(c.execute("select 1 from messages where sha256=?",(digest,)).fetchone() is None, "tombstoned message not re-imported")

# integrity check catches tampering
f = next((tmp/"data"/"u"/"messages").rglob("*.eml")); f.write_bytes(f.read_bytes()+b"x")
rc = imp.main(); check(rc == 2, f"tampered file stops sync (exit {rc})")
shutil.rmtree(tmp); print("ALL PASSED")
