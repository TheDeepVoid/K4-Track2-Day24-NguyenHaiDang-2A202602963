"""BƯỚC 3d — audit ledger append-only, tamper-evident (10')."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path


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
    if path.exists() and path.stat().st_size > 0:
        line = json.dumps(entry, ensure_ascii=False)
        path.write_text(path.read_text(encoding="utf-8") + line + "\n", encoding="utf-8")
    else:
        path.write_text(json.dumps(entry, ensure_ascii=False) + "\n", encoding="utf-8")

    return entry


def verify(path: Path) -> bool:
    """Verify the integrity of the JSONL ledger.

    Checks:
      - Every line has a non-empty `reason`
      - prev_hash of line n matches the hash of line n-1
      - hash of line n matches the computed hash from that line's content

    Returns True if all checks pass, False otherwise.
    Does NOT detect deletion of the last line or full-file rewrites
    without external timestamp reference.
    """
    if not path.exists():
        return True  # empty/non-existent file is trivially valid

    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return True

    prev_hash_expected = "0" * 64

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

        # Set up for next iteration
        prev_hash_expected = entry.get("hash", "")

    return True