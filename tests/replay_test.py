import asyncio
import json
from pathlib import Path
import sys

# Add parent directory to path so we can import client
sys.path.insert(0, str(Path(__file__).parent.parent))

from client import Client

# Monkey-patch to inject a replay
original_on_deliver = Client._on_user_deliver

async def patched_on_deliver(self, msg):
    # Process message normally
    await original_on_deliver(self, msg)
    
    # After 2 seconds, replay it automatically
    await asyncio.sleep(2)
    print("\n[TEST] Replaying the same message...")
    await original_on_deliver(self, msg)

Client._on_user_deliver = patched_on_deliver

# Run the client normally
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="ws://127.0.0.1:8765")
    args = ap.parse_args()
    asyncio.run(Client(args.url).run())