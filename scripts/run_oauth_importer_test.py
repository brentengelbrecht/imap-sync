"""OAuth (IMAP_AUTH=oauth2) importer test against a mock Microsoft endpoint and a fake IMAP server."""
import json, os, subprocess, sys, tempfile, threading, http.server, urllib.parse, sqlite3, contextlib, io
from pathlib import Path
here = Path(__file__).parent; sys.path[:0] = [str(here), str(here.parent)]
from fake_imap_server import FakeImapServer

state = {"rt": "rt1", "n": 1, "at": 0, "polls": 0, "mode": "ok", "token_calls": 0, "fail_next_503": 0}
imap = None
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        f = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode()).items()}
        out, code = {}, 200
        if self.path.endswith("/devicecode"):
            out = {"device_code": "dc", "user_code": "WXYZ-9999", "verification_uri": "https://microsoft.com/devicelogin", "expires_in": 60, "interval": 1}
        elif f["grant_type"].endswith("device_code"):
            state["polls"] += 1
            if state["polls"] < 2: out, code = {"error": "authorization_pending"}, 400
            else: out = self.issue()
        else:
            state["token_calls"] += 1
            if state["fail_next_503"] > 0:
                state["fail_next_503"] -= 1; out, code = {"error": "temporarily_unavailable", "error_description": "busy"}, 503
            elif state["mode"] == "revoked" or f["refresh_token"] != state["rt"]:
                out, code = {"error": "invalid_grant", "error_description": "AADSTS70000 the refresh token was revoked"}, 400
            else: out = self.issue()
        body = json.dumps(out).encode(); self.send_response(code); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def issue(self):
        state["at"] += 1; state["n"] += 1; state["rt"] = f"rt{state['n']}"
        tok = f"opaque-access-{state['at']}"; imap.valid_tokens.add(tok)
        return {"access_token": tok, "refresh_token": state["rt"], "expires_in": 3600}
ms = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=ms.serve_forever, daemon=True).start()
os.environ["IMAP_OAUTH_AUTHORITY_BASE"] = f"http://127.0.0.1:{ms.server_address[1]}"

import logging; logging.basicConfig(level=logging.ERROR)
import imap_local_repository as imp
imp.INITIAL_BACKOFF_SECONDS = 0.05

tmp = Path(tempfile.mkdtemp()); cert, key = tmp/"c.pem", tmp/"k.pem"
subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,"-out",cert,"-days","2","-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost,IP:127.0.0.1"],check=True,capture_output=True)
def msg(n): return b"From: a@x\r\nSubject: m%d\r\nMessage-ID: <%d@x>\r\n\r\nbody %d\r\n" % (n,n,n)
D = "17-Jul-2024 02:44:25 -0700"
imap = FakeImapServer(cert, key); imap.oauth_user = "me@outlook.com"
imap.folders = {"INBOX": {"uidvalidity":1,"flags":[],"msgs":{1:("",D,msg(1)),2:("",D,msg(2))}}}
imap.start()
tokfile = tmp/"tok"/"me.json"
os.environ.update(IMAP_AUTH="oauth2", IMAP_HOST="localhost", IMAP_PORT=str(imap.port), IMAP_USERNAME="me@outlook.com",
    IMAP_OAUTH_CLIENT_ID="cid", IMAP_OAUTH_TOKEN_FILE=str(tokfile), IMAP_CA_FILE=str(cert),
    DB_LOCATION=str(tmp/"data"), IMAP_MIN_FREE_BYTES="0")
os.environ.pop("IMAP_PASSWORD", None)

def check(c, label):
    print("OK  " if c else "FAIL", label)
    if not c: sys.exit(1)
def run(*argv):
    sys.argv = ["imap_local_repository.py", *argv]; out = io.StringIO()
    with contextlib.redirect_stdout(out): rc = imp.main()
    return rc, out.getvalue()
def count(): return sqlite3.connect(tmp/"data"/"me.outlook.com".replace("me.outlook.com","me%40outlook.com")/"repository.db").execute("select count(*) from messages").fetchone()[0]

rc, out = run("--authorise"); check(rc == 0, f"--authorise succeeds (rc {rc})")
check("WXYZ-9999" in out and "devicelogin" in out, "device code and URL shown")
check(tokfile.exists() and oct(tokfile.stat().st_mode & 0o777) == "0o600", "token file saved, chmod 600")
check(json.loads(tokfile.read_text())["refresh_token"] == state["rt"], "saved refresh token is the latest")

rc, _ = run(); check(rc == 0 and count() == 2, "import via XOAUTH2 stores 2 messages")
check(json.loads(tokfile.read_text())["refresh_token"] == state["rt"], "rotated refresh token saved after import")

imap.folders["INBOX"]["msgs"][3] = ("", D, msg(3))
imap.valid_tokens.clear()    # server now rejects every previously issued token
rc, _ = run(); check(rc == 0 and count() == 3, "fresh token obtained and import continues")

imap.folders["INBOX"]["msgs"][4] = ("", D, msg(4)); state["fail_next_503"] = 2; before = state["token_calls"]
rc, _ = run(); check(rc == 0 and count() == 4 and state["token_calls"] - before >= 3, "token endpoint 503s are retried")

# a stale in-memory token within one process: expires_in tiny -> refreshed on reconnect (covered by margin logic)
oauth = imp.MicrosoftOAuth("cid", "consumers", imp.DEFAULT_OAUTH_SCOPES, tokfile)
t1 = oauth.access_token(); t2 = oauth.access_token()
check(t1 == t2 and oauth.token_is_fresh is False, "unexpired access token is cached")

state["mode"] = "revoked"; imap.folders["INBOX"]["msgs"][5] = ("", D, msg(5))
rc, _ = run(); check(rc == 2, f"revoked sign-in exits 2 (got {rc})")
import logging as L
state["mode"] = "ok"

# cached-but-rejected token inside one long-running session: reconnect must refresh and carry on
cfg = imp.get_configuration(); sess = imp.ImapSession(cfg)
sess.list_folders(); first = cfg["oauth"]._access_token
sess._drop(); imap.valid_tokens.clear(); calls = state["token_calls"]
names = [f["name"] for f in sess.list_folders()]
check(names == ["INBOX"] and cfg["oauth"]._access_token != first and state["token_calls"] == calls + 1,
      "cached token rejected -> refreshed once and the session carries on")
sess.close()

os.environ["IMAP_USERNAME"] = "someone-else@outlook.com"; tokfile2 = tmp/"tok"/"other.json"; os.environ["IMAP_OAUTH_TOKEN_FILE"] = str(tokfile2)
state["polls"] = 0; rc, out = run("--authorise")
check(rc == 2 and not tokfile2.exists(), "wrong account: --authorise fails and saves nothing")
os.environ["IMAP_USERNAME"] = "me@outlook.com"; os.environ["IMAP_OAUTH_TOKEN_FILE"] = str(tmp/"tok"/"missing.json")
rc, _ = run(); check(rc == 2, "no token file: exit 2 with guidance")
print("ALL PASSED")
