# tests/interop_smoke.py
# Simple manual checklist helper: prints commands to run.

print("""
Smoke test:

1) In one terminal:
   python server.py --host 127.0.0.1 --port 8765

2) In terminal A:
   python client.py --url ws://127.0.0.1:8765
   (copy your user_id)

3) In terminal B:
   python client.py --url ws://127.0.0.1:8765
   (copy B's user_id)

4) In either client:
   list
   tell <OTHER_USER_UUID> hello
   all hi everyone

Expected:
- Only the target prints the DM plaintext.
- A tampered content_sig is rejected ("bad content signature").
""")