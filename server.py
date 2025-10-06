# server.py
from __future__ import annotations
import asyncio, json, argparse
from pathlib import Path
import time
from collections import deque
import websockets

from modules.crypto_rsa import (
    ensure_rsa_keypair, b64u_encode, rsa_sign_pss,
    load_pub_from_b64u_pem, canon, is_valid_pubkey_len
)
from modules.formats import envelope, payload_list_res

# key storage for the server
KEYDIR = Path.home() / ".yourchat" / "server"
SERVER_ID_FILE = KEYDIR / "server_id.txt"

# in-memory state
CLIENTS = set()          # websockets
USER_BY_WS = {}          # ws -> user_id
PUB_BY_USER = {}         # user_id -> base64url PEM

# simple per-connection rate limiting (sliding window)
RATE_WINDOW_SECS = 10
RATE_LIMIT_MSGS = 20
MSG_TIMESTAMPS = {}  # ws -> deque[timestamps]

# Minimum RSA bits enforced by clean build is controlled centrally in modules.crypto_rsa

def _transport_sign(priv, env_dict: dict) -> str:
    # sign over canonical JSON of {type,from,to,ts_ms,payload}
    signed = {k: env_dict[k] for k in ("type","from","to","ts_ms","payload")}
    return b64u_encode(rsa_sign_pss(priv, canon(signed)))

def _check_rate_limit(ws) -> bool:
    """Return True if allowed, False if rate limited."""
    now = time.time()
    dq = MSG_TIMESTAMPS.setdefault(ws, deque())
    # drop old
    while dq and dq[0] <= now - RATE_WINDOW_SECS:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_MSGS:
        return False
    dq.append(now)
    return True

async def handler(ws, server_id, server_priv):
    # connection established
    print(f"[connect] peer connected: {ws.remote_address}")
    CLIENTS.add(ws)
    MSG_TIMESTAMPS.setdefault(ws, deque())
    try:
        async for raw in ws:
            # rate-limit first: drop excessively chatty clients early
            if not _check_rate_limit(ws):
                # optionally notify client of rate limit but avoid abuse
                try:
                    fail = envelope("ERROR", from_id=server_id, to_id=None, payload={"code":"RATE_LIMIT_EXCEEDED"})
                    fail["sig"] = _transport_sign(server_priv, fail)
                    await ws.send(json.dumps(fail, separators=(",",":")))
                except Exception:
                    pass
                print(f"[rate-limit] dropping message from {ws.remote_address}")
                continue

            # ignore non-JSON
            try:
                msg = json.loads(raw)
            except Exception:
                # silently ignore invalid JSON to avoid crashing on bad clients
                continue

            t = msg.get("type")
            if t == "USER_HELLO":
                user_id = msg.get("from")
                user_pub_b64u = msg.get("payload", {}).get("user_pub")
                if not user_id or not user_pub_b64u:
                    continue

                # load public key (PEM base64url)
                try:
                    pub = load_pub_from_b64u_pem(user_pub_b64u)
                except Exception:
                    print(f"[reject] {user_id} malformed public key")
                    continue

                # validate key length via project's validator (central policy)
                try:
                    if not is_valid_pubkey_len(pub):
                        print(f"[reject] {user_id} weak key {getattr(pub, 'key_size', 'unknown')}")
                        continue
                except Exception as e:
                    print(f"[reject] {user_id} validation error: {e}")
                    continue

                USER_BY_WS[ws] = user_id
                PUB_BY_USER[user_id] = user_pub_b64u
                print(f"[hello] {user_id} online from {ws.remote_address}")

            elif t == "LIST_REQ":
                requester = msg.get("from")
                users = [{"user_id": uid, "user_pub": pub} for uid, pub in PUB_BY_USER.items()]
                env = envelope("LIST_RES", from_id=server_id, to_id=requester, payload=payload_list_res(users))
                env["sig"] = _transport_sign(server_priv, env)
                await ws.send(json.dumps(env, separators=(",",":")))
                print(f"[route] LIST_REQ from {requester} -> {len(users)} users")

            elif t == "MSG_DIRECT":
                sender = msg.get("from")
                to = msg.get("to")

                # find recipient websocket
                target_ws = None
                for c, uid in USER_BY_WS.items():
                    if uid == to:
                        target_ws = c
                        break

                if not target_ws:
                    # inform sender user not found
                    fail = envelope("ERROR", from_id=server_id, to_id=sender, payload={"code":"USER_NOT_FOUND","to":to})
                    fail["sig"] = _transport_sign(server_priv, fail)
                    await ws.send(json.dumps(fail, separators=(",",":")))
                    print(f"[route] MSG_DIRECT from {sender} to {to} failed: user not found")
                    continue

                # Forward the message as-is (server never decrypts ciphertext)
                deliver = {
                    "type": "USER_DELIVER",
                    "from": sender,
                    "to": to,
                    "ts_ms": msg.get("ts_ms"),
                    "payload": msg.get("payload"),
                    "sig": ""
                }
                deliver["sig"] = _transport_sign(server_priv, deliver)

                try:
                    await target_ws.send(json.dumps(deliver, separators=(",",":")))
                    print(f"[route] MSG_DIRECT from {sender} -> {to} delivered")
                except Exception:
                    # if send fails, notify sender
                    fail = envelope("ERROR", from_id=server_id, to_id=sender, payload={"code":"DELIVERY_FAILED","to":to})
                    fail["sig"] = _transport_sign(server_priv, fail)
                    try:
                        await ws.send(json.dumps(fail, separators=(",",":")))
                    except Exception:
                        pass
                    print(f"[route] MSG_DIRECT from {sender} -> {to} failed to send")

            else:
                # unknown message types are ignored for robustness
                continue

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        # cleanup on disconnect
        CLIENTS.discard(ws)
        MSG_TIMESTAMPS.pop(ws, None)
        uid = USER_BY_WS.pop(ws, None)
        if uid and PUB_BY_USER.get(uid):
            print(f"[bye] {uid} offline from {ws.remote_address}")

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
    ap.add_argument("--rate-window", type=int, default=RATE_WINDOW_SECS)
    ap.add_argument("--rate-limit", type=int, default=RATE_LIMIT_MSGS)
    ap.add_argument("--vuln", action="store_true", help="enable vulnerable mode")
    args = ap.parse_args()

    RATE_WINDOW_SECS = args.rate_window
    RATE_LIMIT_MSGS = args.rate_limit

    import sys, config
    config.init_from_argv(sys.argv)
    if args.vuln:
        config.IS_VULN = True
    config.apply_to_crypto()
    print(f"[mode] vulnerable={config.IS_VULN}")

    asyncio.run(main(args.host, args.port))
