# Baseline — Checkpoint 1

1. Agent có identity mỗi run chưa? **Có**, mỗi chạy agent sử dụng `runner.handle()` hoặc `_naive_loop()` với LLM mock deterministic. Identity duy nhất thông qua `principal_id` (support_l1/dpo) và ledger entries.

2. Ai cho phép `http_post`? **File:** `agent/policy.py`, **Hàm:** `check()`. Chỉ cho phép khi `data_classification != "restricted"` hoặc `egress_enabled is False`. Rule tối thiểu: `restricted + egress_enabled -> DENY`.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? **File:** `reports/attack-before.log` (trước khi contain) và `reports/attack-after.log` (sau contain). Khi agent chưa có PEP/containment, `_naive_loop()` trong `agent/loop.py` sẽ đọc customer từ injection và gọi `tools.http_post()` → PII lộ ra sink. Sau khi implement containment (trifecta split + PEP + ledger), `http_post` bị chặn và PII không đậu ra ngoài.
