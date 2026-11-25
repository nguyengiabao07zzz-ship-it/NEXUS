# NEXUS

Ứng dụng web chạy tại máy để đọc cảnh báo Wazuh, gom nhóm và ưu tiên dữ liệu, phân tích bằng AI có duyệt trước, và hỗ trợ tạo bản nháp rule để kiểm thử trên lab.

**Bản sẵn sàng cho kiểm thử lab có giám sát.** Chưa là hệ thống SOC production hoặc bằng chứng về độ chính xác phát hiện. Không tự chạy tấn công, chặn endpoint hay tự cài rule lên Wazuh.

## Chức năng

- Đọc `alerts`/`archives` từ Wazuh Indexer qua HTTPS và SSH tunnel; giữ số lượng khớp, giới hạn và cửa sổ thời gian.
- Tìm kiếm, lọc level, gom agent/rule/decoder, chọn tối đa20event cho mỗi yêu cầu AI. Sắp theo level Wazuh không phải kết luận nguy hiểm.
- Codex CLI đăng nhập ChatGPT hoặc OpenAI Responses API. Luôn có preview, hash, xác nhận gửi và chống gửi lại cùng preview.
- Ngữ cảnh hành vi và MITRE ID; thêm mô tả/trích đoạn đã xử lý chỉ khi người dùng chọn. Không hứa ẩn danh hoàn toàn.
- Lịch sử phân tích/lỗi, xem dẫn chứng, xuất JSON nội bộ. Không biến nhận định AI thành ground truth.
- Đề xuất rule cho ca development, kiểm subsetXML, lưu candidate và xuất bundle Ubuntu lab. Giữ held-out cho đánh giá.
- Helper lab: stage/configtest/logtest/activate/rollback; kích hoạt yêu cầu kiểm thử attack/benign/regression phù hợp và thao tác người dùng.
- Polling tùy chọn, chỉ đọc tại máy, tối đa8giờ/phiên; không tự gọi AI.

## Bắt đầu

Cần Python3.11+; backend chỉ dùng thư viện chuẩn. Không cần build frontend/npm. Windows là nền tảng phát triển đã thử; helper cài rule chỉ chạy trên Ubuntu Wazuh lab.

```powershell
git clone https://github.com/nguyengiabao07zzz-ship-it/NEXUS.git
cd NEXUS
python run_nexus.py --check-codex
```

Lần đầu: cấu hình Indexer và chọn Codex theo [hướng dẫn cài đặt](docs/INSTALL.md). Mở Ubuntu VM khi cần đọc dữ liệu thật. Windows VM chỉ cần khi tạo thêm log endpoint.

Sau khi đã cấu hình, giữ tunnel mở và chạy:

```powershell
python run_nexus.py --ask-indexer-password
```

Mở <http://127.0.0.1:8765>. Nhập mật khẩu tại terminal, không đưa vào source. Không cần API key khi dùng Codex đăng nhập ChatGPT; vẫn chịu hạn mức tài khoản.

Có thể dùng `Start-NEXUS.ps1 -LabHost <IP_UBUNTU>` để mở tunnel và app trong một console. Nếu chính sách máy không cho chạy script, dùng các lệnh Python/SSH riêng trong hướng dẫn; không cần hạ chính sách bảo mật.

## Kiểm thử và tài liệu

```powershell
python -B -m unittest discover -s tests -q
node --check src/nexus/web/app.js
```

Node chỉ dùng để kiểm cú pháp khi phát triển. Tests dùng mock/fixture/HTTPloopback; không tự gọi model hoặc Wazuh thật.

- [Cài đặt, đổi máy và xử lý lỗi](docs/INSTALL.md)
- [Kế hoạch kiểm thử lab](docs/LAB-ACCEPTANCE.md)
- [Kiến trúc và giới hạn](docs/ARCHITECTURE.md)
- [Bằng chứng kiểm chứng bản phát hành](docs/VALIDATION.md)
- [Nhật ký sử dụng AI](research/AI_USAGE.md)

## Dữ liệu và phạm vi

`data/private/` chứa cấu hình máy, SQLite, khóa HMAC, lịch sử và request đã duyệt. Thư mục này bị gitignore và không đi kèm bản source. API key/mật khẩu chỉ nằm trong phiên chạy. Backup private có thể chứa log/định danh: tự bảo vệ và kiểm tra trước khi chia sẻ. Thay định danh không bảo đảm ẩn danh; preview văn bản cần người đọc.

Chỉ bind loopback; không mở app trực tiếp ra Internet. Polling dùng cửa sổ giới hạn, không có pagination/checkpoint bền vững, nên không bảo đảm thu hết log. Thiếu cảnh báo không chứng minh không có tấn công.

Dự án tiếp nối source của nhóm tại [LLM-in-Wazuh](https://github.com/Kokonut-Original/LLM-in-Wazuh). Giữ riêng kết quả lab, hồ sơ nhóm và dữ liệu runtime; không công bố số liệu phát hiện chưa được đo. Bản cập nhật này không cấp thêm giấy phép cho mã có trước.
