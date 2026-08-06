"""Generate a per-client token + AES-256 key, register it in the store.

Usage:
    python keygen.py [--label friendly-name] [--count N] [--db path]

Output: prints one line per token:
    <token> <aes_key_hex> <label>
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys

from store import Store

TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def new_token() -> str:
    return "miau_" + "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(32))


def main() -> int:
    ap = argparse.ArgumentParser(description="Miau token generator")
    ap.add_argument("--label", default="", help="friendly label")
    ap.add_argument("--count", type=int, default=1, help="how many tokens")
    ap.add_argument("--db", default="./miau.db", help="store path")
    args = ap.parse_args()

    store = Store(args.db)
    for i in range(args.count):
        token = new_token()
        key = os.urandom(32)
        label = args.label or f"client-{i + 1}"
        store.add_token(token, key, label)
        print(f"{token} {key.hex()} {label}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
