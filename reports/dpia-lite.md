# Đánh giá tác động dữ liệu (DPIA) - bản tin cỉng

## 1. Loại dữ liệu và phân loại

| Loại dữ liệu | Phân loại | Ví dụ trong lab |
|---|---|---|
| CCCD (Chứng minh công dân) | Ri tư | `811753472374`, `304918277561` |
| SĐT (Số điện thoại) | Ri tư | `0861707895`, `0938114772` |
| Tài khoản ngân hàng | Ri tư | `9103069783`, `5520417398` |
| Email | Ri tư | `le.thu.trang666@example.vn` |
| Tên khách hàng | Công khai | Lê Thu Trang, Bùi Khánh Vy |

## 2. Mục đích xử lý và principal

| Mục đích | Principal | Quyền được cấp |
|---|---|---|
| Tổng hợp tổng đài | `support_l1` | Chỉ `search_docs` |
| Phản hồi hỗ trợ khách | `dpo` | `search_docs`, `read_customer` (cho ticket hợp lệ) |
| Đối soát giao dịch | `run-b` | `search_docs`, `read_customer` |

## 3. Dữ liệu đi qua những run/tool nào, endpoint nào

| Run | Tool | Endpoint | Mô tả |
|---|---|---|---|
| Run A | `search_docs()` | `corpus/*.md` | Đọc nội dung ticket (chứa payload injection) |
| Run B | `read_customer()` | `data/customers.json` | Đọc record khách theo ticket ID từ filename |
| Tất cả | `http_post()` | `127.0.0.1:10024/reconcile` | POST dữ liệu — **chặn** bởi policy (restricted + egress → deny) |

## 4. Bằng chứng deny/allow và giới hạn của mock

| Kiểm soát | Kết quả | Giới hạn |
|---|---|---|
| **PEP deny** (restricted + egress) | ✅ Đã chặn — `policy.check()` trả `allow=False` | Chỉ cho mock data, không ảnh hưởng system thật |
| **Containment (trifecta split)** | ✅ Không đọc KH-000777 chỉ qua free text | Cần ticket ID hợp lệ từ filename → related_tickets |
| **Ledger hash chain** | ✅ `verify()` through — 180 entries, tamper-detectable | Không phát hiện xoá dòng cuối (cần mốc tin cậy ngoài) |
| **PII redaction** | ✅ `redact()` thay CCCD/SDT/email bằng `[REDACTED_TYPE]` | Chỉ trên data tổng hợp, không áp được trên channel thật |
| **Gitleaks scanner** | ✅ Phát hiện token giả tại commit `1bdd849` | Không phát hiện credential thật (không có) |

## 5. Giới hạn của mock setup

- Dữ liệu là **synthetic**, không phải patient/data thật
- Agent chạy trong environment kiểm soát (localhost only)
- Không có kết nối đến external services thật
- Không thể khẳng định tuân thủ điều khoản pháp luật cụ thể
- Chỉ mục đích: chứng minh kỹ thuật containment trong lab

## 6. Kết luận

DPIA cho lab Day 24 cho thấy:
- **Rủi ro**: Prompt injection có thể làm agent đọc dữ liệu cá nhân và POST ra sink
- **Phòng chống**: Trifecta split + PEP + ledger tạo layered defense
- **Giảm thiểu**: Mock data cho phép test mà không rủi ro thực
- **Khuyến nghị**: Áp dụng nguyên lý least privilege, audit logging, và containment giống như đã implement trong lab này cho hệ thống thật