# server.py
from __future__ import annotations
import asyncio, json, argparse
from pathlib import Path
import websockets

from modules.crypto_rsa import ensure_rsa_keypair, b64u_encode, b64u_decode, rsa_sign_pss, load_pub_from_b64u_pem, canon
from modules.formats import envelope, payload_list_res

# key storage for the server
KEYDIR = Path.home() / ".yourchat" / "server"
SERVER_ID_FILE = KEYDIR / "server_id.txt"

# in-memory state
CLIENTS = set()          # websockets
USER_BY_WS = {}          # ws -> user_id
PUB_BY_USER = {}         # user_id -> base64url PEM

def _transport_sign(priv, env_dict: dict) -> str:
    # sign over canonical JSON of {type,from,to,ts_ms,payload}
    signed = {k: env_dict[k] for k in ("type","from","to","ts_ms","payload")}
    return b64u_encode(rsa_sign_pss(priv, canon(signed)))

async def handler(ws, server_id, server_priv):
    CLIENTS.add(ws)
    try:
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except Exception:
                continue

            t = msg.get("type")
            if t == "USER_HELLO":
                user_id = msg.get("from")
                user_pub_b64u = msg.get("payload", {}).get("user_pub")
                if not user_id or not user_pub_b64u:
                    continue
                # (clean build) reject weak keys < 4096 bits
                try:
                    pub = load_pub_from_b64u_pem(user_pub_b64u)
                    if getattr(pub, "key_size", 0) < 4096:
                        # comment out this block in the vuln branch
                        print(f"[reject] {user_id} weak key {pub.key_size}")
                        continue
                except Exception:
                    continue
                USER_BY_WS[ws] = user_id
                PUB_BY_USER[user_id] = user_pub_b64u
                print(f"[hello] {user_id} online")
            elif t == "LIST_REQ":
                users = [{"user_id": uid, "user_pub": pub} for uid, pub in PUB_BY_USER.items()]
                env = envelope("LIST_RES", from_id=server_id, to_id=msg.get("from"), payload=payload_list_res(users))
                env["sig"] = _transport_sign(server_priv, env)
                await ws.send(json.dumps(env, separators=(",",":")))
            elif t == "MSG_DIRECT":
                sender = msg.get("from")
                to = msg.get("to")
                # find recipient
                target_ws = None
                for c, uid in USER_BY_WS.items():
                    if uid == to:
                        target_ws = c
                        break
                if not target_ws:
                    # optional: tell sender error
                    fail = envelope("ERROR", from_id=server_id, to_id=sender, payload={"code":"USER_NOT_FOUND","to":to})
                    fail["sig"] = _transport_sign(server_priv, fail)
                    await ws.send(json.dumps(fail, separators=(",",":")))
                    continue
                deliver = envelope("USER_DELIVER", from_id=sender, to_id=to, payload=msg["payload"])
                deliver["sig"] = _transport_sign(server_priv, deliver)
                await target_ws.send(json.dumps(deliver, separators=(",",":")))
            else:
                pass
    finally:
        CLIENTS.discard(ws)
        uid = USER_BY_WS.pop(ws, None)
        if uid and PUB_BY_USER.get(uid):
            print(f"[bye] {uid} offline")

async def main(host: str, port: int):
    KEYDIR.mkdir(parents=True, exist_ok=True)
    server_priv, _server_pub = ensure_rsa_keypair(KEYDIR, "server")
    if SERVER_ID_FILE.exists():
        server_id = SERVER_ID_FILE.read_text().strip()
    else:
        import uuid
        server_id = str(uuid.uuid4()); SERVER_ID_FILE.write_text(server_id)

    async with websockets.serve(lambda ws: handler(ws, server_id, server_priv), host, port):
        print(f"[server] {server_id} ws://{host}:{port}")
        await asyncio.Future()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    asyncio.run(main(args.host, args.port))
