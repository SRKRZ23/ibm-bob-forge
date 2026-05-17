"""
FORGE BobShell — IBM Bob action audit log.

Every FORGE action (scan, generate, verify) is logged as a BobShell entry.
BobShell is a tamper-evident JSON-lines log that serves as a compliance artifact:
  - Timestamp of each action
  - Action type + parameters
  - SHA-256 hash of the output
  - Chain hash linking all entries (tamper-evident)
  - IBM Bob session ID

Used for enterprise compliance: demonstrates that FORGE scanned the actual
repository and generated the actual policy — not a fabricated report.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


GENESIS_HASH = "0" * 64
BOBSHELL_VERSION = "1.0"  # Schema version for future compatibility


def _validate_hash(hash_str: str) -> bool:
    """
    Validate that a string is a valid SHA-256 hash.
    
    Security: Prevents injection of malformed hashes that could break chain verification.
    
    Args:
        hash_str: String to validate as SHA-256 hash
    
    Returns:
        True if valid SHA-256 hash format, False otherwise
    """
    if not isinstance(hash_str, str):
        return False
    if len(hash_str) != 64:
        return False
    # Must be 64 hexadecimal characters
    return bool(re.match(r'^[0-9a-f]{64}$', hash_str))


def _validate_timestamp(timestamp: str) -> bool:
    """
    Validate timestamp format and check for manipulation.
    
    Security: Prevents backdating or future-dating of audit entries.
    
    Args:
        timestamp: ISO 8601 timestamp string
    
    Returns:
        True if valid and reasonable timestamp, False otherwise
    """
    if not isinstance(timestamp, str):
        return False
    
    # Check format: YYYY-MM-DDTHH:MM:SS
    if not re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$', timestamp):
        return False
    
    try:
        # Parse timestamp
        ts_struct = time.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
        ts_epoch = time.mktime(ts_struct)
        
        # Security: Check timestamp is not too far in the past (> 1 year)
        one_year_ago = time.time() - (365 * 24 * 60 * 60)
        if ts_epoch < one_year_ago:
            return False
        
        # Security: Check timestamp is not in the future (allow 5 min clock skew)
        future_threshold = time.time() + (5 * 60)
        if ts_epoch > future_threshold:
            return False
        
        return True
    except (ValueError, OverflowError):
        return False


def _sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


@dataclass
class BobShellEntry:
    seq: int
    timestamp: str
    action: str
    params: dict
    output_hash: str
    prev_hash: str
    entry_hash: str
    bob_session_id: str
    version: str = BOBSHELL_VERSION  # Schema version for future compatibility

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "action": self.action,
            "params": self.params,
            "output_hash": self.output_hash,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "bob_session_id": self.bob_session_id,
        }


class BobShell:
    """
    Append-only tamper-evident log for FORGE/IBM Bob actions.
    Chain: each entry commits to the hash of all previous entries.
    """

    def __init__(self, session_id: Optional[str] = None):
        import uuid
        self.session_id = session_id or f"bob_{uuid.uuid4().hex[:12]}"
        self._entries: list[BobShellEntry] = []
        self._prev_hash = GENESIS_HASH
        self._seq = 0

    def log(self, action: str, params: dict, output: str | dict) -> BobShellEntry:
        # Security: Validate action string
        if not isinstance(action, str) or len(action) == 0 or len(action) > 256:
            raise ValueError("Invalid action: must be non-empty string <= 256 chars")
        
        # Security: Validate params is a dict
        if not isinstance(params, dict):
            raise ValueError("Invalid params: must be a dictionary")
        
        output_str = json.dumps(output, sort_keys=True) if isinstance(output, dict) else str(output)
        output_hash = _sha256(output_str)
        
        # Security: Validate output hash format
        if not _validate_hash(output_hash):
            raise ValueError(f"Invalid output hash format: {output_hash}")
        
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        
        # Security: Validate timestamp
        if not _validate_timestamp(ts):
            raise ValueError(f"Invalid or manipulated timestamp: {ts}")
        
        # Security: Validate prev_hash format
        if not _validate_hash(self._prev_hash):
            raise ValueError(f"Invalid prev_hash format: {self._prev_hash}")

        payload = json.dumps({
            "version": BOBSHELL_VERSION,
            "seq": self._seq,
            "ts": ts,
            "action": action,
            "params": params,
            "output_hash": output_hash,
            "prev_hash": self._prev_hash,
        }, sort_keys=True)
        entry_hash = _sha256(payload)
        
        # Security: Validate computed entry hash
        if not _validate_hash(entry_hash):
            raise ValueError(f"Invalid entry hash format: {entry_hash}")

        entry = BobShellEntry(
            seq=self._seq,
            timestamp=ts,
            action=action,
            params=params,
            output_hash=output_hash,
            prev_hash=self._prev_hash,
            entry_hash=entry_hash,
            bob_session_id=self.session_id,
            version=BOBSHELL_VERSION,
        )
        self._entries.append(entry)
        self._prev_hash = entry_hash
        self._seq += 1
        return entry

    def verify(self) -> bool:
        """
        Verify chain integrity. Returns False if any entry is tampered.
        
        Security: Validates hash formats, timestamp integrity, and chain linking.
        """
        prev = GENESIS_HASH
        for entry in self._entries:
            # Security: Validate hash formats
            if not _validate_hash(entry.prev_hash):
                return False
            if not _validate_hash(entry.entry_hash):
                return False
            if not _validate_hash(entry.output_hash):
                return False
            
            # Security: Validate timestamp
            if not _validate_timestamp(entry.timestamp):
                return False
            
            # Verify chain link
            if entry.prev_hash != prev:
                return False
            
            # Reconstruct payload with version field
            payload = json.dumps({
                "version": entry.version,
                "seq": entry.seq,
                "ts": entry.timestamp,
                "action": entry.action,
                "params": entry.params,
                "output_hash": entry.output_hash,
                "prev_hash": entry.prev_hash,
            }, sort_keys=True)
            expected_hash = _sha256(payload)
            
            if entry.entry_hash != expected_hash:
                return False
            
            prev = entry.entry_hash
        return True

    def export(self) -> dict:
        return {
            "bob_session_id": self.session_id,
            "total_actions": len(self._entries),
            "chain_verified": self.verify(),
            "entries": [e.to_dict() for e in self._entries],
        }

    def write_jsonl(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            for entry in self._entries:
                f.write(json.dumps(entry.to_dict()) + "\n")

    def __len__(self) -> int:
        return len(self._entries)
