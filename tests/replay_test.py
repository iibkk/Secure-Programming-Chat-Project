import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

import config
from client import Client

class ReplayTestClient(Client):
    """Client that automatically replays the first message it receives"""
    
    def __init__(self, url: str):
        super().__init__(url)
        self.first_message = None
        self.replayed = False
    
    async def _on_user_deliver(self, msg: dict):
        await super()._on_user_deliver(msg)
        
        if not self.first_message:
            self.first_message = msg
            print("\n[TEST] First message captured, will replay in 2 seconds...")
            await asyncio.sleep(2)
            print("[TEST] Now replaying the same message...\n")
            await super()._on_user_deliver(msg)
            self.replayed = True

if __name__ == "__main__":
    import argparse
    
    config.init_from_argv(sys.argv)
    config.apply_to_crypto()
    
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="ws://127.0.0.1:8765")
    ap.add_argument("--vuln", action="store_true", help="Run in vulnerable mode")
    args = ap.parse_args()
    
    print(f"[TEST MODE] Running in {'VULNERABLE' if config.IS_VULN else 'CLEAN'} mode")
    print(f"[TEST MODE] Replay guard is {'DISABLED' if config.IS_VULN else 'ENABLED'}")
    print()
    
    asyncio.run(ReplayTestClient(args.url).run())