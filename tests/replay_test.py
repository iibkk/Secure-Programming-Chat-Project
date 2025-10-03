import asyncio
import json
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from client import Client

class ReplayTestClient(Client):
    """Client that automatically replays the first message it receives"""
    
    def __init__(self, url: str):
        super().__init__(url)
        self.first_message = None
        self.replayed = False
    
    async def _on_user_deliver(self, msg: dict):
        # Call the original handler
        await super()._on_user_deliver(msg)
        
        # Store first message and replay it after a delay
        if not self.first_message:
            self.first_message = msg
            print("\n[TEST] First message captured, will replay in 2 seconds...")
            await asyncio.sleep(2)
            print("[TEST] Now replaying the same message...\n")
            await super()._on_user_deliver(msg)
            self.replayed = True

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="ws://127.0.0.1:8765")
    args = ap.parse_args()
    asyncio.run(ReplayTestClient(args.url).run())