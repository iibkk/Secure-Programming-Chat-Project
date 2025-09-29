# config.py
"""
Global run-mode config for the chat project.

Usage (in server.py / client.py):
    import sys, config
    config.init_from_argv(sys.argv)   # reads --vuln or env YOURCHAT_MODE
    config.apply_to_crypto()          # propagates to modules.crypto_rsa.VULN_WEAK_KEYS

Then elsewhere you can check:
    if config.IS_VULN: ...
"""

import os
from typing import Sequence

# Default = clean build
IS_VULN: bool = False

def init_from_argv(argv: Sequence[str]) -> None:
    """
    Set IS_VULN from CLI / environment.
    - Pass '--vuln' on the command line to enable vulnerable mode.
    - Or set environment variable YOURCHAT_MODE=vuln.
    """
    global IS_VULN
    # env wins if set explicitly
    mode_env = os.getenv("YOURCHAT_MODE", "").strip().lower()
    if mode_env in {"vuln", "vulnerable"}:
        IS_VULN = True
        return
    if mode_env in {"clean", "secure"}:
        IS_VULN = False
        return

    # otherwise, look for --vuln in argv
    IS_VULN = any(arg == "--vuln" for arg in argv or ())

def apply_to_crypto() -> None:
    """
    Propagate current mode to the crypto module so weak keys are allowed only in vuln builds.
    Call this once at program start after init_from_argv().
    """
    try:
        from modules import crypto_rsa as C
        C.VULN_WEAK_KEYS = IS_VULN
    except Exception:
        # If crypto module isn't importable yet, we just skip.
        # Call this again later after imports if needed.
        pass
