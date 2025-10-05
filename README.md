# Secure-Programming-Advanced-Secure-Protocol-Design-Implementation-and-Review-Project

# Introduction
The goal was to design and implement a secure chat protocol, test it, and reflect on its strengths and weaknesses.  

This `README.md` describes the **clean (secure) build** of the system. A separate file, `README_VULN.md`, explains the intentionally vulnerable version we are submitting for peer review.

---

# System Overview
Our chat application provides:
- WebSocket-based communication** between clients and a central server.
- End-to-end encryption** using RSA-OAEP (SHA-256).
- Integrity protection** via RSA-PSS signatures.
- Replay attack protection** through client-side duplicate detection.
- Key enforcement** — only strong keys (>= 4096 bits) are accepted in clean mode.

The server only routes messages and never decrypts payloads. All sensitive operations remain client-side.

---

# Repository Layout
- "server.py" — Routing server (keeps directory of users, forwards encrypted DMs).  
- "client.py" — Interactive command-line chat client.  
- "modules/crypto_rsa.py" — RSA helper functions (key generation, encrypt/decrypt, sign/verify).  
- "modules/formats.py" — Defines JSON envelopes and payload formats.  
- "config.py" — Global mode configuration (secure vs vulnerable).  
- "protocol.md" — Protocol specification and rules.  
- "tests/interop_smoke.py" — Manual interop test steps.  
- "tests/replay_test.py" — Replay test client (to demonstrate the difference between secure and vulnerable modes).  
- "requirements.txt" — Python dependencies.  

---

# Setup
--- bash
python -m venv .venv
source .venv/bin/activate     # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
---

# Start the server
python server.py --host 127.0.0.1 --port 8765

--- 

# Start clients (in separate terminals)
python client.py --url ws://127.0.0.1:8765

---

# Commands

list = show all online users
tell <user_id> <message> = send encrypted DM
all <message> = broadcast a message to all users
quit = exit

--- 

# Example Workflow

Start the server.
Start two clients.
- In Client A:
- list
- tell <ID_User_B> hello
Client B should see the decrypted message.
Try 'all hi everyone' to test broadcast.

---

# Clients
python client.py --url ws://127.0.0.1:8765 --vuln

--- 


# Expected Behaviour in Vulnerable Mode

Server accepts weaker keys.
Replay guard is disabled → duplicate messages are accepted.
Other subtle flaws are present, which reviewers are expected to detect.

---
