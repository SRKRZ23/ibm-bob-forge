"""
Unit tests for FORGE BobShell Audit Logger (bobshell.py).

Tests cover:
- Audit chain integrity
- Hash linking between entries
- Tamper detection
- Chain verification
- JSONL export
"""
import pytest
import json
import hashlib
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from audit.bobshell import (
    BobShell,
    BobShellEntry,
    _sha256,
    GENESIS_HASH,
)


class TestSHA256Utility:
    """Test the SHA-256 hashing utility function."""
    
    def test_sha256_string_input(self):
        """Test SHA-256 hashing with string input."""
        result = _sha256("test")
        
        assert isinstance(result, str)
        assert len(result) == 64  # SHA-256 produces 64 hex characters
        # Verify against known hash
        expected = hashlib.sha256(b"test").hexdigest()
        assert result == expected
    
    def test_sha256_bytes_input(self):
        """Test SHA-256 hashing with bytes input."""
        result = _sha256(b"test")
        
        assert isinstance(result, str)
        assert len(result) == 64
        expected = hashlib.sha256(b"test").hexdigest()
        assert result == expected
    
    def test_sha256_deterministic(self):
        """Test that SHA-256 is deterministic."""
        input_data = "deterministic test"
        hash1 = _sha256(input_data)
        hash2 = _sha256(input_data)
        
        assert hash1 == hash2
    
    def test_sha256_different_inputs(self):
        """Test that different inputs produce different hashes."""
        hash1 = _sha256("input1")
        hash2 = _sha256("input2")
        
        assert hash1 != hash2


class TestBobShellEntry:
    """Test the BobShellEntry dataclass."""
    
    def test_entry_creation(self):
        """Test creating a BobShellEntry."""
        entry = BobShellEntry(
            seq=0,
            timestamp="2026-05-17T05:00:00",
            action="test_action",
            params={"key": "value"},
            output_hash="abc123",
            prev_hash=GENESIS_HASH,
            entry_hash="def456",
            bob_session_id="bob_test123"
        )
        
        assert entry.seq == 0
        assert entry.action == "test_action"
        assert entry.params == {"key": "value"}
        assert entry.prev_hash == GENESIS_HASH
    
    def test_entry_to_dict(self):
        """Test converting entry to dictionary."""
        entry = BobShellEntry(
            seq=1,
            timestamp="2026-05-17T05:00:00",
            action="test_action",
            params={"test": "data"},
            output_hash="hash1",
            prev_hash="hash0",
            entry_hash="hash2",
            bob_session_id="bob_session"
        )
        
        entry_dict = entry.to_dict()
        
        assert isinstance(entry_dict, dict)
        assert entry_dict["seq"] == 1
        assert entry_dict["action"] == "test_action"
        assert entry_dict["params"] == {"test": "data"}
        assert entry_dict["bob_session_id"] == "bob_session"


class TestBobShellInitialization:
    """Test BobShell initialization."""
    
    def test_bobshell_init_default(self):
        """Test BobShell initialization with default session ID."""
        bob = BobShell()
        
        assert bob.session_id.startswith("bob_")
        assert len(bob.session_id) == 16  # "bob_" + 12 hex chars
        assert len(bob._entries) == 0
        assert bob._prev_hash == GENESIS_HASH
        assert bob._seq == 0
    
    def test_bobshell_init_custom_session(self):
        """Test BobShell initialization with custom session ID."""
        bob = BobShell(session_id="custom_session_123")
        
        assert bob.session_id == "custom_session_123"
        assert len(bob._entries) == 0
    
    def test_bobshell_len(self):
        """Test BobShell __len__ method."""
        bob = BobShell()
        assert len(bob) == 0
        
        bob.log("action1", {}, "output1")
        assert len(bob) == 1
        
        bob.log("action2", {}, "output2")
        assert len(bob) == 2


class TestBobShellLogging:
    """Test BobShell logging functionality."""
    
    def test_log_single_entry(self):
        """Test logging a single entry."""
        bob = BobShell()
        
        entry = bob.log("test_action", {"param": "value"}, "test output")
        
        assert isinstance(entry, BobShellEntry)
        assert entry.seq == 0
        assert entry.action == "test_action"
        assert entry.params == {"param": "value"}
        assert entry.prev_hash == GENESIS_HASH
        assert len(bob._entries) == 1
    
    def test_log_multiple_entries(self):
        """Test logging multiple entries."""
        bob = BobShell()
        
        entry1 = bob.log("action1", {"p1": "v1"}, "output1")
        entry2 = bob.log("action2", {"p2": "v2"}, "output2")
        entry3 = bob.log("action3", {"p3": "v3"}, "output3")
        
        assert len(bob._entries) == 3
        assert entry1.seq == 0
        assert entry2.seq == 1
        assert entry3.seq == 2
    
    def test_log_chain_linking(self):
        """Test that entries are properly linked in chain."""
        bob = BobShell()
        
        entry1 = bob.log("action1", {}, "output1")
        entry2 = bob.log("action2", {}, "output2")
        entry3 = bob.log("action3", {}, "output3")
        
        # Verify chain links
        assert entry1.prev_hash == GENESIS_HASH
        assert entry2.prev_hash == entry1.entry_hash
        assert entry3.prev_hash == entry2.entry_hash
    
    def test_log_with_dict_output(self):
        """Test logging with dictionary output."""
        bob = BobShell()
        
        output_dict = {"result": "success", "count": 42}
        entry = bob.log("test_action", {}, output_dict)
        
        # Should hash the JSON representation
        expected_hash = _sha256(json.dumps(output_dict, sort_keys=True))
        assert entry.output_hash == expected_hash
    
    def test_log_with_string_output(self):
        """Test logging with string output."""
        bob = BobShell()
        
        output_str = "test output string"
        entry = bob.log("test_action", {}, output_str)
        
        expected_hash = _sha256(output_str)
        assert entry.output_hash == expected_hash
    
    def test_log_increments_sequence(self):
        """Test that sequence number increments correctly."""
        bob = BobShell()
        
        for i in range(5):
            entry = bob.log(f"action{i}", {}, f"output{i}")
            assert entry.seq == i
        
        assert bob._seq == 5


class TestBobShellVerification:
    """Test BobShell chain verification."""
    
    def test_verify_empty_chain(self):
        """Test verification of empty chain."""
        bob = BobShell()
        
        assert bob.verify() is True
    
    def test_verify_valid_chain(self):
        """Test verification of valid chain."""
        bob = BobShell()
        
        bob.log("action1", {"p1": "v1"}, "output1")
        bob.log("action2", {"p2": "v2"}, "output2")
        bob.log("action3", {"p3": "v3"}, "output3")
        
        assert bob.verify() is True
    
    def test_verify_detects_tampered_params(self):
        """Test that verification detects tampered parameters."""
        bob = BobShell()
        
        bob.log("action1", {"original": "value"}, "output1")
        bob.log("action2", {"p2": "v2"}, "output2")
        
        # Tamper with first entry's params
        bob._entries[0].params["tampered"] = "data"
        
        # Verification should fail
        assert bob.verify() is False
    
    def test_verify_detects_tampered_output_hash(self):
        """Test that verification detects tampered output hash."""
        bob = BobShell()
        
        bob.log("action1", {}, "output1")
        bob.log("action2", {}, "output2")
        
        # Tamper with output hash
        bob._entries[0].output_hash = "tampered_hash"
        
        assert bob.verify() is False
    
    def test_verify_detects_broken_chain_link(self):
        """Test that verification detects broken chain links."""
        bob = BobShell()
        
        bob.log("action1", {}, "output1")
        bob.log("action2", {}, "output2")
        bob.log("action3", {}, "output3")
        
        # Break the chain by modifying prev_hash
        bob._entries[2].prev_hash = "broken_link"
        
        assert bob.verify() is False
    
    def test_verify_detects_reordered_entries(self):
        """Test that verification detects reordered entries."""
        bob = BobShell()
        
        bob.log("action1", {}, "output1")
        bob.log("action2", {}, "output2")
        bob.log("action3", {}, "output3")
        
        # Swap entries (breaks chain)
        bob._entries[1], bob._entries[2] = bob._entries[2], bob._entries[1]
        
        assert bob.verify() is False
    
    def test_verify_detects_modified_entry_hash(self):
        """Test that verification detects modified entry hash."""
        bob = BobShell()
        
        bob.log("action1", {}, "output1")
        bob.log("action2", {}, "output2")
        
        # Modify entry hash directly
        bob._entries[0].entry_hash = "modified_hash"
        
        assert bob.verify() is False


class TestBobShellExport:
    """Test BobShell export functionality."""
    
    def test_export_structure(self):
        """Test export produces correct structure."""
        bob = BobShell(session_id="test_session")
        
        bob.log("action1", {"p1": "v1"}, "output1")
        bob.log("action2", {"p2": "v2"}, "output2")
        
        export = bob.export()
        
        assert isinstance(export, dict)
        assert "bob_session_id" in export
        assert "total_actions" in export
        assert "chain_verified" in export
        assert "entries" in export
        
        assert export["bob_session_id"] == "test_session"
        assert export["total_actions"] == 2
        assert export["chain_verified"] is True
        assert len(export["entries"]) == 2
    
    def test_export_includes_all_entries(self):
        """Test that export includes all logged entries."""
        bob = BobShell()
        
        for i in range(5):
            bob.log(f"action{i}", {"seq": i}, f"output{i}")
        
        export = bob.export()
        
        assert len(export["entries"]) == 5
        for i, entry in enumerate(export["entries"]):
            assert entry["seq"] == i
            assert entry["action"] == f"action{i}"
    
    def test_export_verifies_chain(self):
        """Test that export includes chain verification status."""
        bob = BobShell()
        
        bob.log("action1", {}, "output1")
        bob.log("action2", {}, "output2")
        
        # Valid chain
        export = bob.export()
        assert export["chain_verified"] is True
        
        # Tamper and re-export
        bob._entries[0].params["tampered"] = True
        export_tampered = bob.export()
        assert export_tampered["chain_verified"] is False


class TestBobShellJSONLExport:
    """Test BobShell JSONL file export."""
    
    def test_write_jsonl_creates_file(self, tmp_path):
        """Test that write_jsonl creates a file."""
        bob = BobShell()
        bob.log("action1", {"p1": "v1"}, "output1")
        bob.log("action2", {"p2": "v2"}, "output2")
        
        output_file = tmp_path / "test_bobshell.jsonl"
        bob.write_jsonl(output_file)
        
        assert output_file.exists()
    
    def test_write_jsonl_format(self, tmp_path):
        """Test that write_jsonl produces valid JSONL format."""
        bob = BobShell()
        bob.log("action1", {"p1": "v1"}, "output1")
        bob.log("action2", {"p2": "v2"}, "output2")
        
        output_file = tmp_path / "test_bobshell.jsonl"
        bob.write_jsonl(output_file)
        
        # Read and verify JSONL format
        with open(output_file) as f:
            lines = f.readlines()
        
        assert len(lines) == 2
        
        # Each line should be valid JSON
        for line in lines:
            entry = json.loads(line)
            assert "seq" in entry
            assert "action" in entry
            assert "entry_hash" in entry
    
    def test_write_jsonl_preserves_data(self, tmp_path):
        """Test that write_jsonl preserves all entry data."""
        bob = BobShell(session_id="test_session")
        bob.log("action1", {"key": "value"}, "output1")
        
        output_file = tmp_path / "test_bobshell.jsonl"
        bob.write_jsonl(output_file)
        
        # Read back and verify
        with open(output_file) as f:
            entry = json.loads(f.readline())
        
        assert entry["seq"] == 0
        assert entry["action"] == "action1"
        assert entry["params"] == {"key": "value"}
        assert entry["bob_session_id"] == "test_session"
    
    def test_write_jsonl_creates_parent_dirs(self, tmp_path):
        """Test that write_jsonl creates parent directories."""
        bob = BobShell()
        bob.log("action1", {}, "output1")
        
        # Path with non-existent parent directories
        output_file = tmp_path / "nested" / "dir" / "bobshell.jsonl"
        bob.write_jsonl(output_file)
        
        assert output_file.exists()
        assert output_file.parent.exists()


class TestBobShellIntegration:
    """Integration tests for BobShell."""
    
    def test_full_audit_workflow(self, tmp_path):
        """Test complete audit workflow: log → verify → export."""
        bob = BobShell(session_id="integration_test")
        
        # Log multiple actions
        bob.log("scan_start", {"repo": "/test/repo"}, "started")
        bob.log("scan_complete", {"files": 10, "findings": 5}, {"summary": "done"})
        bob.log("policy_generated", {"policy_name": "test_policy"}, "policy.yaml")
        bob.log("policy_written", {"path": "/output/policy.yaml"}, "/output/policy.yaml")
        
        # Verify chain
        assert bob.verify() is True
        assert len(bob) == 4
        
        # Export to dict
        export = bob.export()
        assert export["total_actions"] == 4
        assert export["chain_verified"] is True
        
        # Write to JSONL
        output_file = tmp_path / "audit.jsonl"
        bob.write_jsonl(output_file)
        assert output_file.exists()
        
        # Verify JSONL content
        with open(output_file) as f:
            lines = f.readlines()
        assert len(lines) == 4
    
    def test_tamper_detection_workflow(self):
        """Test that tampering is detected throughout workflow."""
        bob = BobShell()
        
        # Create valid chain
        bob.log("action1", {"data": "original"}, "output1")
        bob.log("action2", {"data": "original"}, "output2")
        bob.log("action3", {"data": "original"}, "output3")
        
        # Verify valid
        assert bob.verify() is True
        
        # Tamper with middle entry
        bob._entries[1].params["data"] = "tampered"
        
        # Should detect tampering
        assert bob.verify() is False
        
        # Export should reflect tampering
        export = bob.export()
        assert export["chain_verified"] is False
    
    def test_genesis_hash_constant(self):
        """Test that GENESIS_HASH is correct constant."""
        assert GENESIS_HASH == "0" * 64
        assert len(GENESIS_HASH) == 64
    
    def test_multiple_bobshell_instances_independent(self):
        """Test that multiple BobShell instances are independent."""
        bob1 = BobShell(session_id="session1")
        bob2 = BobShell(session_id="session2")
        
        bob1.log("action1", {}, "output1")
        bob2.log("action2", {}, "output2")
        
        assert len(bob1) == 1
        assert len(bob2) == 1
        assert bob1.session_id != bob2.session_id
        assert bob1._entries[0].entry_hash != bob2._entries[0].entry_hash
