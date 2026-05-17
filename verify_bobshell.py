#!/usr/bin/env python3
"""Verify BobShell tamper-evident SHA-256 hash chain from a .jsonl audit log.

Usage:  python3 verify_bobshell.py <path/to/bobshell.jsonl>
"""
import json
import hashlib
import sys
from pathlib import Path

GENESIS_HASH = "0" * 64


def verify_chain(jsonl_path: Path) -> tuple[bool, int, str]:
    prev = GENESIS_HASH
    n = 0
    with jsonl_path.open() as f:
        for line in f:
            entry = json.loads(line)
            payload = json.dumps({
                "version": entry["version"],
                "seq": entry["seq"],
                "ts": entry["timestamp"],
                "action": entry["action"],
                "params": entry["params"],
                "output_hash": entry["output_hash"],
                "prev_hash": entry["prev_hash"],
            }, sort_keys=True)
            expected = hashlib.sha256(payload.encode()).hexdigest()
            if entry["entry_hash"] != expected:
                return False, n, f"hash mismatch at seq {entry['seq']}"
            if entry["prev_hash"] != prev:
                return False, n, f"chain broken at seq {entry['seq']}"
            prev = entry["entry_hash"]
            n += 1
    return True, n, "SHA-256 tamper-evident"


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python3 verify_bobshell.py <path/to/bobshell.jsonl>", file=sys.stderr)
        return 1
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        return 1
    ok, n, msg = verify_chain(path)
    status = "verified" if ok else "FAILED"
    print(f"BobShell chain {status}: {n} entries, {msg}")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
