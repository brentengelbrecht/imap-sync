"""Tiny in-process IMAP server (implicit TLS) for testing the importer."""
import asyncio, re, ssl, threading

class FakeImapServer:
    def __init__(self, certfile, keyfile, user="u", password="p"):
        self.folders = {}      # raw name -> {"uidvalidity": int, "flags": [..], "msgs": {uid: (flags, date, bytes)}}
        self.user, self.password = user, password
        self.drop_on_fetch = None   # drop the connection once at the Nth fetch
        self.fetch_count = 0
        self.fetch_log = []
        self.certfile, self.keyfile = certfile, keyfile
        self.port = None
        self._ready = threading.Event()

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True); self.thread.start()
        self._ready.wait(5)

    def _run(self):
        self.loop = asyncio.new_event_loop(); asyncio.set_event_loop(self.loop)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(self.certfile, self.keyfile)
        server = self.loop.run_until_complete(asyncio.start_server(self._client, "127.0.0.1", 0, ssl=ctx))
        self.port = server.sockets[0].getsockname()[1]; self._ready.set()
        self.loop.run_forever()

    async def _client(self, r, w):
        w.write(b"* OK fake IMAP ready\r\n"); sel = None
        while True:
            line = await r.readline()
            if not line: break
            m = re.match(rb"(\S+) (\S+)(?: (.*))?\r\n", line)
            tag, cmd, arg = m.group(1), m.group(2).upper(), (m.group(3) or b"").decode()
            if cmd == b"CAPABILITY":
                w.write(b"* CAPABILITY IMAP4rev1\r\n")
            elif cmd == b"LOGIN":
                u, p = re.findall(r'"((?:[^"\\]|\\.)*)"|(\S+)', arg)[:2]
                if (u[0] or u[1]) != self.user or (p[0] or p[1]) != self.password:
                    w.write(tag + b" NO [AUTHENTICATIONFAILED] bad login\r\n"); await w.drain(); continue
            elif cmd == b"LIST":
                for name, f in self.folders.items():
                    fl = " ".join(f["flags"])
                    w.write(f'* LIST ({fl}) "/" "{name}"\r\n'.encode())
            elif cmd in (b"EXAMINE", b"SELECT"):
                name = arg.strip().strip('"')
                if name not in self.folders:
                    w.write(tag + b" NO no such mailbox\r\n"); await w.drain(); continue
                sel = self.folders[name]
                w.write(f"* {len(sel['msgs'])} EXISTS\r\n* OK [UIDVALIDITY {sel['uidvalidity']}] ok\r\n".encode())
            elif cmd == b"UID":
                sub, rest = arg.split(" ", 1)
                if sub.upper() == "SEARCH":
                    w.write(b"* SEARCH " + " ".join(map(str, sorted(sel["msgs"]))).encode() + b"\r\n")
                elif sub.upper() == "FETCH":
                    uid = int(rest.split()[0]); self.fetch_count += 1
                    if self.drop_on_fetch and self.fetch_count == self.drop_on_fetch:
                        w.close(); return
                    self.fetch_log.append(uid)
                    if uid in sel["msgs"]:
                        fl, date, body = sel["msgs"][uid]
                        w.write(f'* 1 FETCH (UID {uid} FLAGS ({fl}) INTERNALDATE "{date}" BODY[] {{{len(body)}}}\r\n'.encode() + body + b")\r\n")
            elif cmd == b"LOGOUT":
                w.write(b"* BYE bye\r\n" + tag + b" OK done\r\n"); await w.drain(); w.close(); return
            w.write(tag + b" OK done\r\n"); await w.drain()
