# Dấu chính tuân thủ - Checkpoint 5

| Nguồn / yêu cầu | Control đã làm | Evidence file: dòng | Giới hạn |
|---|---|---|---|
| **Luật 91/2025/QH15** (Luật An toàn thông tin) | - Phân loại dữ liệu riêng (CCCD, SĐT, bank account)<br>- Nguyên tắc tối thiểu: chỉ chia sẻ khi cần thiết<br>- Yêu cầu bảo vệ dữ liệu cá nhân | `reports/pii.py` - hàm detect/type<br>`reports/ledger.jsonl` - ghi audit trail | Chỉ áp dụng cho dữ liệu tổng hợp mock, không thể đảm bảo cho dữ liệu thật |
| **NĐ 356/2025/NĐ-CP** (Luật Bảo mật an toàn thông tin) | - Áp dụng cho dữ liệu cá nhân trong hệ thống<br>- Yêu cầu xác thực, bảo mật, truy xuất | `reports/policy.py` - kiểm tra principal/classification<br>`reports/ledger.jsonl` - mỗi hành động có reason | Mock data không tạo ra nghĩa vụ pháp lý thực |
| **Luật AI 134/2025/QH15** | - Yêu cầu an toàn cho hệ thống AI<br>- AI không được tạo ra rò rỉ dữ liệu cá nhân | `reports/agent/runner.py` - containment (trifecta split)<br>`reports/policy.py` - PEP chặn egress | Chỉ mô phỏng an toàn, không chứng minh tuân thủ thực |
| **OWASP ASI01/03/04** (AI Security Incidents) | - ASI01: Phòng chống prompt injection<br>- ASI03: Quản lý quyền truy cập<br>- ASI04: Bảo vệ dữ liệu nhạy cảm | `reports/agent/runner.py` - containment against injection<br>`reports/policy.py` - policy enforcement<br>`reports/agent/ledger.py` - audit & accountability | Mô phỏng Lab, không có endpoints thật |

## Ghi chú
- Tất cả control được triển khai trên dữ liệu **tổng hợp/synthetic** (`data/customers.json`, `corpus/`)
- Không sử dụng credential hoặc PII thật nào
- Mock environment giới hạn việc chứng minh tuân thủ pháp lý cụ thể
- Mục đích: thể hiện kỹ thuật containment và audit khả thi