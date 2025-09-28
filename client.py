# client.py
from __future__ import annotations
import asyncio, json, argparse, sys
from pathlib import Path
import websockets

from modules.crypto_rsa import (
    ensure_rsa_keypair, b64u_encode, b64u_decode, load_pub_from_b64u_pem,
    rsa_encrypt_oaep, rsa_decrypt_oaep, rsa_sign_pss, rsa_verify_pss,
    new_uuid, canon, RSA_OAEP_SHA256_MAX_PT
)
from modules.formats import (
    envelope, payload_user_hello, payload_list_req, payload_msg_direct, content_sig_material
)

# storage for the client
KEYDIR = Path.home() / ".yourchat" / "client"
USER_ID_FILE = KEYDIR / "user_id.txt"

# Clean build: enable replay guard. In vuln branch set this to False.
ENABLE_REPLAY_GUARD = True

class Client:
    def __init__(self, url: str):
        KEYDIR.mkdir(parents=True, exist_ok=True)
        self.priv, self.pub_pem = ensure_rsa_keypair(KEYDIR, "user")
        if USER_ID_FILE.exists():
            self.user_id = USER_ID_FILE.read_text().strip()
        else:
            self.user_id = new_uuid(); USER_ID_FILE.write_text(self.user_id)
        self.url = url
        self.pub_b64u = b64u_encode(self.pub_pem)
        self.directory: dict[str, str] = {}  # user_id -> pub_b64u
        self.seen = set()

    async def run(self):
        async with websockets.connect(self.url) as ws:
            print(f"[you] user_id={self.user_id}")
            # announce
            hello = envelope("USER_HELLO", from_id=self.user_id, to_id=None,
                             payload=payload_user_hello(self.pub_b64u))
            await ws.send(json.dumps(hello, separators=(",",":")))

            async def reader():
                async for raw in ws:
                    try:
                        msg = json.loads(raw)
                    except Exception:
                        continue
                    t = msg.get("type")
                    if t == "LIST_RES":
                        users = msg.get("payload", {}).get("users", [])
                        self.directory = {u["user_id"]: u["user_pub"] for u in users if "user_id" in u and "user_pub" in u}
                        print("[list]")
                        for uid in sorted(self.directory.keys()):
                            you = " (you)" if uid == self.user_id else ""
                            print(" -", uid, you)
                    elif t == "USER_DELIVER":
                        await self._on_user_deliver(msg)
                    elif t == "ERROR":
                        print("[ERROR]", msg.get("payload"))
                    else:
                        pass

            async def writer():
                loop = asyncio.get_event_loop()
                print("commands: list | tell <user_uuid> <text> | all <text> | quit")
                while True:
                    line = await loop.run_in_executor(None, sys.stdin.readline)
                    if not line:
                        continue
                    line = line.strip()
                    if line == "quit":
                        break
                    if line == "list":
                        req = envelope("LIST_REQ", from_id=self.user_id, to_id=None, payload=payload_list_req())
                        await ws.send(json.dumps(req, separators=(",",":")))
                        continue
                    if line.startswith("tell "):
                        parts = line.split(" ", 2)
                        if len(parts) < 3:
                            print("usage: tell <user_uuid> <text>"); continue
                        uid, text = parts[1], parts[2]
                        await self._send_dm(ws, uid, text)
                        continue
                    if line.startswith("all "):
                        text = line[len("all "):]
                        await self._send_all(ws, text)
                        continue
                    print("unknown command")

            await asyncio.gather(reader(), writer())

    async def _send_dm(self, ws, to_id: str, text: str):
        if to_id == self.user_id:
            print("won't tell yourself"); return
        pub_b64u = self.directory.get(to_id)
        if not pub_b64u:
            print("unknown user; run 'list'"); return
        pt = text.encode("utf-8")
        if len(pt) > RSA_OAEP_SHA256_MAX_PT:
            print(f"message too long for RSA-4096 OAEP ({len(pt)} > {RSA_OAEP_SHA256_MAX_PT} bytes)"); return
        peer_pub = load_pub_from_b64u_pem(pub_b64u)
        
        # Encrypt the message
        ct = rsa_encrypt_oaep(peer_pub, pt)
        ciphertext_b64u = b64u_encode(ct)
        
        # Create envelope with ciphertext but placeholder signature
        env = envelope("MSG_DIRECT", from_id=self.user_id, to_id=to_id, 
                    payload=payload_msg_direct(self.pub_b64u, ciphertext_b64u, ""))
        
        # Generate and set the content signature
        content_sig = rsa_sign_pss(self.priv, content_sig_material(env))
        env["payload"]["content_sig"] = b64u_encode(content_sig)
        
        await ws.send(json.dumps(env, separators=(",",":")))

    async def _send_all(self, ws, text: str):
        # simple fan-out DM to each known peer (except self)
        for uid in list(self.directory.keys()):
            if uid != self.user_id:
                await self._send_dm(ws, uid, text)

    async def _on_user_deliver(self, msg: dict):
        pay = msg["payload"]
        try:
            sender_pub = load_pub_from_b64u_pem(pay["sender_pub"])
        except Exception:
            print("[WARN] bad sender key; dropped"); return
        mat = content_sig_material(msg)
        if not rsa_verify_pss(sender_pub, mat, b64u_decode(pay["content_sig"])):
            print("[WARN] bad content signature; dropped"); return
        # replay guard (disable in vuln branch)
        if ENABLE_REPLAY_GUARD:
            from hashlib import sha256
            digest = sha256(mat).hexdigest()
            if digest in self.seen:
                print("[WARN] duplicate (replay) dropped"); return
            self.seen.add(digest)
        try:
            pt = rsa_decrypt_oaep(self.priv, b64u_decode(pay["ciphertext"]))
        except Exception as e:
            print("[WARN] decrypt failed:", e); return
        print(f"[dm {msg['from'][:8]}→you] {pt.decode('utf-8', errors='replace')}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="ws://127.0.0.1:8765")
    args = ap.parse_args()
    asyncio.run(Client(args.url).run())
