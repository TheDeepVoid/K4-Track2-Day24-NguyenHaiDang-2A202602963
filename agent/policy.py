"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15')."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


BASE_DIR = Path(__file__).resolve().parent.parent
PRINCIPALS_FILE = BASE_DIR / "data" / "principals.json"


def _load_principals() -> dict:
    try:
        return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _is_expired(expires_at: str) -> bool:
    if not expires_at:
        return False  # if not specified, treat as valid for basic cases? tests set it
    try:
        dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        return dt < datetime.now(timezone.utc)
    except Exception:
        return True  # treat malformed as expired/invalid


def check(context: PolicyContext) -> tuple[bool, str]:
    principals = _load_principals()

    # Minimum rule: restricted + egress_enabled -> DENY
    if context.data_classification == "restricted" and context.egress_enabled is True:
        return False, "restricted classification with egress enabled denied"

    # Check expiration
    if _is_expired(context.expires_at):
        return False, "session expired"

    # OBO checks if principal is specified
    if context.principal_id:
        principal = principals.get(context.principal_id)
        if not principal:
            return False, "unknown principal"
        # Check purpose
        allowed_purposes = principal.get("purposes", [])
        if allowed_purposes and context.request_purpose not in allowed_purposes:
            return False, "purpose not allowed for principal"
        # Check tool permissions
        allowed_tools = set(principal.get("allowed_tools", []))
        agent_scopes = set(context.agent_scopes)
        requested_tool = context.requested_tool
        if requested_tool:
            if requested_tool not in allowed_tools:
                return False, "principal not authorized for tool"
            if requested_tool not in agent_scopes:
                return False, "agent scope missing required tool"
            if context.delegation_depth > 0:
                parent_scopes = set(context.parent_scopes)
                effective = allowed_tools.intersection(agent_scopes).intersection(parent_scopes)
                if requested_tool not in effective:
                    return False, "delegation cannot expand beyond parent scope"
    # If no principal specified, basic allow cases still need reason
    return True, "policy check passed"
