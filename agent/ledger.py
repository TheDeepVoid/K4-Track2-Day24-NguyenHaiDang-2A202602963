"""BƯỚC 3d — audit ledger append-only, tamper-evident (10')."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone


def _compute_hash(entry: dict) -> str:
    """Compute SHA-256 hash of an entry (excluding the `hash` field).

    Uses sorted keys so field order doesn't affect the hash.
    """
    entry_copy = {k: v for k, v in entry.items() if k != "hash"}
    payload = json.dumps(entry_copy, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Append an entry to the JSONL ledger with hash chain.

    Entry must have minimum fields: ts, agent_id, run_id, tool, args_hash,
    classification, decision, reason.

    The function adds:
      - prev_hash: hash of previous line, or "0" * 64 for first entry
      - hash: SHA-256 of this entry's content (including prev_hash)

    Returns the full dict including computed prev_hash and hash.
    """
    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # Read previous hash (from existing file, if any)
    prev_hash = "0" * 64
    if path.exists() and path.stat().st_size > 0:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
            if lines:
                last_entry = json.loads(lines[-1])
                prev_hash = last_entry.get("hash", "0" * 64)
        except (json.JSONDecodeError, OSError):
            prev_hash = "0" * 64

    # Compute this entry's hash
    entry_hash = _compute_hash({**entry, "prev_hash": prev_hash})

    # Attach chain fields
    entry["prev_hash"] = prev_hash
    entry["hash"] = entry_hash

    # Append as JSON line
    line = json.dumps(entry, ensure_ascii=False)
    if path.exists() and path.stat().st_size > 0:
        path.write_text(path.read_text(encoding="utf-8") + line + "\n", encoding="utf-8")
    else:
        path.write_text(line + "\n", encoding="utf-8")

    # Record the last N hashes for deletion detection (bonus feature)
    _record_last_hash(path, entry_hash)

    return entry


def _record_last_hash(path: Path, current_hash: str, max_records: int = 10) -> None:
    """Record the last N hashes for deletion detection (bonus feature).

    Stores a metadata file (.ledger_meta.json) alongside the ledger.
    Tracks the last N hash values. If the number of recorded hashes
    decreases or goes out of order, deletion is detected.

    This is the "delete cascade" bonus feature: it doesn't prevent deletion
    but provides evidence and partial detection.
    """
    meta_path = path.parent / (path.stem + ".meta.json")

    records: list[str] = []
    if meta_path.exists():
        try:
            meta_data = json.loads(meta_path.read_text(encoding="utf-8"))
            records = meta_data.get("last_hashes", [])
        except (json.JSONDecodeError, OSError):
            records = []

    # Add current hash, keep only last max_records (avoid duplicates)
    if current_hash not in records:
        records.append(current_hash)
        if len(records) > max_records:
            records = records[-max_records:]

    try:
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(json.dumps({"last_hashes": records}, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass  # If we can't write metadata, at least the main ledger is valid


def verify(path: Path, *, check_deletion: bool = False) -> bool:
    """Verify the integrity of the JSONL ledger.

    Checks:
      - Every line has a non-empty `reason`
      - prev_hash of line n matches the hash of line n-1
      - hash of line n matches the computed hash from that line's content

    Args:
        path: Path to the ledger JSONL file.
        check_deletion: If True, also check for line deletion using
            the recorded hash history (bonus feature).

    Returns:
        True if all checks pass, False otherwise.
    """
    if not path.exists():
        return True  # empty/non-existent file is trivially valid

    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return True

    prev_hash_expected = "0" * 64

    # Collect hashes for deletion detection
    verified_hashes: list[str] = []

    for i, line in enumerate(lines):
        if not line.strip():
            continue
        entry = json.loads(line)

        # Check reason is non-empty
        if not entry.get("reason"):
            return False

        # Check prev_hash chain
        if i == 0:
            # First entry should have prev_hash = "0" * 64
            if entry.get("prev_hash") != "0" * 64:
                return False
        else:
            # prev_hash should match previous entry's hash
            if entry.get("prev_hash") != prev_hash_expected:
                return False

        # Verify this entry's hash
        computed = _compute_hash({k: v for k, v in entry.items() if k != "hash"})
        if entry.get("hash") != computed:
            return False

        # Track hashes for deletion detection
        verified_hashes.append(entry.get("hash", ""))

        # Set up for next iteration
        prev_hash_expected = entry.get("hash", "")

    # Deletion check (bonus feature)
    if check_deletion and verified_hashes:
        return _check_deletion(verified_hashes, path)

    return True


def _check_deletion(verified_hashes: list[str], path: Path) -> bool:
    """Check for line deletion by comparing recorded hash history.

    This is a best-effort check: we verify that the number of hashes we
    verified matches what we'd expect. If the file has been truncated (last
    line removed), the hash chain will still be internally consistent but
    the count will be off.

    Also check the metadata file for hash count consistency.
    """
    # Check metadata file
    meta_path = path.parent / (path.stem + ".meta.json")
    if not meta_path.exists():
        # No metadata recorded; can only do a basic consistency check
        return True  # Can't verify without metadata

    try:
        meta_data = json.loads(meta_path.read_text(encoding="utf-8"))
        recorded_hashes = meta_data.get("last_hashes", [])
    except (json.JSONDecodeError, OSError):
        return True  # Corrupt metadata, skip deletion check

    # If recorded hashes list is shorter than verified hashes, lines were deleted
    # (the metadata got out of sync because lines were removed)
    if len(recorded_hashes) < len(verified_hashes):
        return False

    # Verify that the most recent recorded hash matches the last verified hash
    if recorded_hashes and verified_hashes:
        if recorded_hashes[-1] != verified_hashes[-1]:
            # Last hash doesn't match - deletion or modification occurred
            return False

    return True