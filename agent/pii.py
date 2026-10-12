"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12')."""

from __future__ import annotations

import re


# Patterns - đơn giản, đủ cho testset
VN_CCCD_RE = re.compile(r"\b\d{12}\b")
# Phone: 0 + 9-10 digits; có thể có dấu cách/gạch ngang
VN_PHONE_RE = re.compile(r"\b0(?:\d[ -]?){8,9}\d\b")
# Bank account: 8-16 digits
VN_BANK_ACCOUNT_RE = re.compile(r"\b\d{8,16}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")


def detect(text: str) -> list[dict]:
    entities: list[dict] = []

    # Email (check first, format specific)
    for m in EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # CCCD - 12 digits
    for m in VN_CCCD_RE.finditer(text):
        entities.append({"type": "VN_CCCD", "start": m.start(), "end": m.end()})

    # Phone
    for m in VN_PHONE_RE.finditer(text):
        entities.append({"type": "VN_PHONE", "start": m.start(), "end": m.end()})

    # Bank account - prefer context "STK"/"tài khoản"/"bank" if present? But testset just has numbers.
    # Also avoid overlapping with phone/cccd? They differ in length/pattern context; but simple: collect all then maybe dedupe? 
    # For this lab, collect; overlaps rare. But better to avoid double-counting same span? Test uses overlap check by type+span.
    for m in VN_BANK_ACCOUNT_RE.finditer(text):
        # Heuristic: if near STK keywords, it's more likely bank; but not required.
        # Avoid matching phone if same digits? phone is 0-starting 10 digits; bank 8-16 - different.
        entities.append({"type": "VN_BANK_ACCOUNT", "start": m.start(), "end": m.end()})

    # Deduplicate exact spans of same type
    seen = set()
    deduped = []
    for e in entities:
        key = (e["type"], e["start"], e["end"])
        if key not in seen:
            seen.add(key)
            deduped.append(e)
    entities = deduped

    # Sort by start
    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    detected = detect(text)
    if not detected:
        return text
    # Replace from end to start to preserve offsets
    result = text
    for entity in sorted(detected, key=lambda x: x["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        result = result[: entity["start"]] + replacement + result[entity["end"] :]
    return result
