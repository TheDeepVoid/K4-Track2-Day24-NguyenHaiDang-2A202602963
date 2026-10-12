"""BƯỚC 3c — trifecta split + egress allowlist (13')."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


def _load_customers() -> list[dict]:
    try:
        return json.loads(
            (Path(__file__).resolve().parent.parent / "data" / "customers.json").read_text(encoding="utf-8")
        )
    except Exception:
        return []


def _extract_ticket_ids(docs: list[dict]) -> set[int]:
    """Extract numeric ticket IDs from document filenames.

    This is the NGUỒN TIN CẬY — ticket IDs derived from filenames,
    NOT from attacker free text.
    """
    ticket_ids: set[int] = set()
    for d in docs:
        fname = d["id"]  # e.g., "ticket-007.md"
        base = fname.replace("ticket-", "").replace(".md", "")
        for part in base.split():
            try:
                ticket_ids.add(int(part))
            except ValueError:
                pass
    return ticket_ids


def _is_customer_via_ticket(customer_id: str, ticket_id: int,
                             customers: list[dict]) -> bool:
    """Check if customer_id is linked to ticket_id via related_tickets."""
    for c in customers:
        if c["customer_id"] == customer_id and ticket_id in c.get("related_tickets", []):
            return True
    return False


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    """Trifecta split-aware agent loop with PEP and ledger.

    Run A: search_docs only (untrusted content). Extract ticket IDs from
    filenames, NOT from attacker free text.
    Run B: read_customer only with ticket-derived IDs via related_tickets.

    Every tool call goes through policy.check() first and is logged to ledger.
    """
    # Run A: search docs from corpus (untrusted content)
    docs = tools.search_docs(message)
    combined_text = "\n\n".join(d["text"] for d in docs)

    # Detect injection markers via LLM
    injected = llm.find_injection(combined_text)

    # Ensure log_dir has ledger
    ledger_path = (log_dir or Path(".")) / "ledger.jsonl"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)

    # Extract ticket IDs from document filenames (the trusted source)
    ticket_ids = _extract_ticket_ids(docs)
    customers = _load_customers()

    results: list[dict] = []

    # --- Process Run B: read customers linked via related_tickets ---
    # This runs regardless of whether injection is detected.
    # The containment guarantee comes from: we only read customers who are
    # linked to ticket IDs from filenames, NOT from attacker free text.
    
    for ticket_id in sorted(ticket_ids):
        # For each ticket found, read customers who have this ticket
        # in their related_tickets
        for customer_id in [c["customer_id"] for c in customers
                           if ticket_id in c.get("related_tickets", [])]:
            # --- Policy check BEFORE tool execution ---
            ctx = policy.PolicyContext(
                data_classification="restricted",
                request_purpose="support-reply",
                agent_owner="lab24-agent",
                delegation_depth=0,
                egress_enabled=False,
                principal_id=principal_id,
                requested_tool="read_customer",
                agent_scopes=("search_docs", "read_customer"),
                parent_scopes=(),
                expires_at="2099-01-01T00:00:00+00:00",
            )
            allowed, reason = policy.check(ctx)

            # Always append to ledger (even when denied)
            ledger.append(
                {
                    "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "agent_id": "lab24-agent",
                    "run_id": "run-a",
                    "tool": "read_customer",
                    "args_hash": hashlib.sha256(customer_id.encode("utf-8")).hexdigest()[:32],
                    "classification": "restricted",
                    "decision": "allow" if allowed else "deny",
                    "reason": reason,
                    "on_behalf_of": principal_id,
                    "expires_at": "2099-01-01T00:00:00+00:00",
                },
                ledger_path,
            )

            if allowed:
                try:
                    record = tools.read_customer(customer_id)
                    results.append(record)
                except tools.ToolError:
                    pass

    # Also detect injection and process those customer_ids,
    # but only if they come from legitimate ticket mappings
    if injected is not None:
        # For each customer_id the LLM detected, verify it comes from a
        # legitimate ticket mapping (via related_tickets), NOT from attacker
        # free text. Only read customers who are linked to one of the
        # ticket IDs we found in Run A.

        valid_customer_ids: list[str] = []

        for customer_id in injected.customer_ids:
            # Check if this customer is linked to ANY of our ticket IDs
            is_valid = False
            for tid in ticket_ids:
                if _is_customer_via_ticket(customer_id, tid, customers):
                    is_valid = True
                    break
            if is_valid and customer_id not in valid_customer_ids:
                valid_customer_ids.append(customer_id)

        # For valid customer IDs from injection, also go through policy
        # (avoid double-processing if already handled above)
        for customer_id in valid_customer_ids:
            # Skip if already processed above (same customer_id might be
            # linked to a ticket we already handled)
            already_processed = any(
                r.get("args_hash", "") == hashlib.sha256(customer_id.encode("utf-8")).hexdigest()[:32]
                for r in results
            )
            if already_processed:
                continue

            # --- Policy check BEFORE tool execution ---
            ctx = policy.PolicyContext(
                data_classification="restricted",
                request_purpose="support-reply",
                agent_owner="lab24-agent",
                delegation_depth=0,
                egress_enabled=False,
                principal_id=principal_id,
                requested_tool="read_customer",
                agent_scopes=("search_docs", "read_customer"),
                parent_scopes=(),
                expires_at="2099-01-01T00:00:00+00:00",
            )
            allowed, reason = policy.check(ctx)

            # Always append to ledger (even when denied)
            ledger.append(
                {
                    "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "agent_id": "lab24-agent",
                    "run_id": "run-a",
                    "tool": "read_customer",
                    "args_hash": hashlib.sha256(customer_id.encode("utf-8")).hexdigest()[:32],
                    "classification": "restricted",
                    "decision": "allow" if allowed else "deny",
                    "reason": reason,
                    "on_behalf_of": principal_id,
                    "expires_at": "2099-01-01T00:00:00+00:00",
                },
                ledger_path,
            )

            if allowed:
                try:
                    record = tools.read_customer(customer_id)
                    results.append(record)
                except tools.ToolError:
                    pass

    # Run B summary: return what we safely collected
    return llm.summarize(docs)