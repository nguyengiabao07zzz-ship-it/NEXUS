# Nhật ký hỗ trợ AI và kiểm chứng

## Bản lab 25/11/2026

AI hỗ trợ viết adapter Wazuh/Codex/OpenAI, profile dữ liệu, triage/rule schema, lịch sử, polling, helper lab, UI, tests và tài liệu. Nhóm vẫn cần đọc và giải thích code, kiểm nội dung model và khai báo việc dùng AI theo quy định nghiên cứu.

108 unit/HTTP loopback tests đạt trên máy Windows trước phát hành; tests dùng fixture/mock, không gọi AI hoặc Wazuh thật. JS syntax và hai script PowerShell được kiểm tra. Browser fixture đi hết preview/consent/triage/rule_draft/save/export/history/polling; kết quả fixture không là nhận định model.

Hai smoke Codex thật ở vòng context/rule mới chỉ dùng JSON tổng hợp, không chứa log Wazuh hoặc PII: triage JSON hợp lệ (8942 input/408 output tokens), rule_draft proposed hợp lệ (9020 input/375 output tokens). Có tiêu hao hạn mức Codex. Các smoke trước đó cũng chỉ kiểm kết nối/định dạng bằng fixture; không tính thành số liệu phát hiện.

Đường Indexer và triage trên log thật đã được thử ở giai đoạn tích hợp; output thiếu ngữ cảnh được dùng làm căn cứ sửa profile. Không công bố raw logs/credentials hoặc gán nhãn ground truth từ AI. Các số đếm cảnh báo là dữ liệu truy vấn, không phải số tấn công.

Helper stage/logtest/activate/rollback chỉ được kiểm bằng command mock/filesystem tạm ở vòng phát hành. Không chạy tấn công, không cài rule lên VM và không xác nhận efficacy trên bộ benign/held-out. Cần nghiệm thu theo docs/LAB-ACCEPTANCE.md.

Source công khai được chọn từ workspace phát triển; hồ sơ nhóm, lịch sử có đường dẫn máy, tài liệu cá nhân, data/private, CA, auth và log không được xuất bản.


## 25/11/2026 — Sửa hai lỗi được review trên da84d3e

Tái hiện lỗi trước sửa bằng fixture/HTTP nội bộ. Cho phép đánh giá candidate development bất biến trên held-out, pin candidate hash/ca nguồn; vẫn chặn phát triển rule từ held-out và dùng candidate khác ca cho development. Tách grouping event đã parse khỏi parser file1 MB để Indexer chấp nhận phản hồi hợp lệ tới2 MB, không serialize lại gây phình UTF-8. Thêm10 regression tests; toàn bộ118tests đạt tại máy. Không gọi AI, không gửi log lab hoặc chạy lệnh Wazuh trong lượt sửa. Bổ sung hướng dẫn phân biệt tuned-evaluation và tuning; CI của commit mới được kiểm sau push.
