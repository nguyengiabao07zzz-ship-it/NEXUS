# Cài đặt NEXUS

## Thành phần

- Máy chạy NEXUS: Python3.11+, OpenSSH client và Codex CLI tương thích nếu chọn Codex.
- Ubuntu VM: Wazuh manager/indexer/dashboard, Indexer HTTPS và SSH truy cập được từ máy thật.
- Windows VM: Wazuh agent; Sysmon chỉ khi kịch bản thử yêu cầu. Không cần cài NEXUS trong cả hai VM.

Không có package Python bắt buộc ngoài stdlib. Tải source từ repo và chạy `python run_nexus.py --help`. File cấu hình mẫu nằm trong `config/`; không sao chép nguyên đường dẫn CA mẫu.

## Cấu hình lần đầu

1. Mở Ubuntu VM. Kiểm tra IP bằng `hostname -I`, phiên bản Wazuh và trạng thái service trên VM. Chỉ dùng mạng lab bạn kiểm soát.
2. Xác minh fingerprint SSH khi kết nối lần đầu. Mở tunnel trong một PowerShell riêng, thay `IP_UBUNTU`:

```powershell
ssh -N -T -a -o ExitOnForwardFailure=yes -L 127.0.0.1:19200:127.0.0.1:9200 student@IP_UBUNTU
```

Sau nhập password, SSH không hiện thêm chữ là bình thường. Giữ cửa sổ mở. Không cần mở port9200 ra mạng.

3. Lấy **chứng chỉ CA công khai** của Indexer từ quản trị lab, đối chiếu fingerprint bằng kênh bạn tin cậy. Không sao chép private key của server. Lưu CA tại máy chạy NEXUS; không commit. URL qua tunnel chỉ hợp lệ nếu tên/IP khớp SAN chứng chỉ; không tắt verify khi không khớp.
4. Đăng nhập Codex tại máy. `codex login` mở trình duyệt để đăng nhập ChatGPT; nếu lệnh không có PATH nhưng đã có app Codex, NEXUS sẽ tìm CLI trong gói app Windows.
5. Từ gốc source chạy:

```powershell
python run_nexus.py --setup-indexer --setup-codex
```

Nhập URL `https://127.0.0.1:19200`, username Indexer có quyền đọc, đường dẫn CA đã xác minh và mật khẩu tại terminal. Account admin trong lab vẫn có quyền admin; việc client chỉ gọi `_search` không làm account thành read-only. Nên dùng account đọc riêng khi quản trị lab đã chuẩn bị.

Codex mặc định chọn `gpt-6.1-sol`; đổi bằng `--codex-model MODEL_ID` khi tài khoản hỗ trợ. Không nhập API key cho Codex ChatGPT sign-in. Kiểm tra `python run_nexus.py --check-codex` trước khi dùng.

Muốn chọn OpenAI API thay Codex: `python run_nexus.py --setup-ai --ask-indexer-password`. Chọn model hỗ trợ Structured Outputs, giới hạnoutput512–4096 và nhập secret API key tạiTTY. API billing/quota độc lập với cấu hình Codex; không có paid call khi khởi động.

## Những lần sau

Mở Ubuntu VM và tunnel rồi chạy:

```powershell
python run_nexus.py --ask-indexer-password
```

Với provider API thêm `--ask-ai-key`. Với provider Codex không thêm flag này. Truy cập <http://127.0.0.1:8765>. Ctrl+C dừng app; đóng tunnel khi xong.

Launcher tùy chọn `./Start-NEXUS.ps1 -LabHost IP_UBUNTU` dùng Codex, hỏi SSH password rồi Indexer password. Nó chỉ dọn processSSH do nó tạo; không dừng tunnel có sẵn. Script chỉ dành Windows và cấu hình tunnel19200. Máy có chính sách chặn script có thể dùng hai lệnhSSH/Python riêng.

## Sử dụng

Kết nối Wazuh → chọn alerts/archives, khoảng thời gian, số lượng và agent → đọc dữ liệu. Archives cần được bật/index trước. Bắt đầu với24giờ nếu lab ít sự kiện; kiểm thời gian UTC giữa các máy.

Chọn group hoặc vị trí event. Profile mặc định không gửi trích đoạn tự do; nếu cần, chọn thêm mô tả/trích đoạn, tạo preview rồi đọc toàn bộ nội dung đã xử lý. Kiểm ruleID/decoder/ngữ cảnh và dữ liệu riêng trước khi tích đồng ý. Gửi sẽ dùng hạn mức/chi phí của provider; không retry ngầm.

Lịch sử AI giữ cả lỗi và kết quả. Yêu cầu interrupted/pending không chứng minh dịch vụ chưa xử lý; không gửi lại hàng loạt. Phiên preview/snapshot hết hạn sau15phút và mất khi app restart.

Đề xuất rule: tạo ca development với tiêu chí rõ, chọn mục đích rule_draft và ca tương ứng. Xem XML/giả định/benign tests, chủ động lưu candidate rồi xuất bundle. Đọc hướng dẫn trong ZIP trước thao tác Ubuntu. Không dùng held-out để tinh chỉnh.

## Xử lý lỗi

- Không kết nối Indexer: kiểm Ubuntu và tunnel19200; `python run_nexus.py --doctor` chỉ kiểm config/TCP, không xác minh account/query.
- `codex_not_found`: mở terminal mới hoặc cài/mở app Codex chính thức cho đúng userWindows. NEXUS không dùng launcher `.cmd/.bat` qua shell.
- `codex_login_required`: đăng nhập ChatGPT bằng CLI, không dùng Tracking ID hay APIkey để thay phiên ChatGPT.
- `codex_run_failed`: kiểm đăng nhập, model, mạng và hạn mức; không tự retry. CLI phải hỗ trợ ignore-user-config/ephemeral/output-schema.
- API401: nhập secret key đầy đủ, không dùng Tracking ID. API429: kiểm billing/quota/rate limit, không gửi liên tục.
- TLS lỗi: xác minh CA/tênmáy. Adapter API có fallback public Windows Root store nếu Python chưa có CA; không tắt TLS verification.
- Cổng8765 bị chiếm: Ctrl+C ở cửa sổ NEXUS cũ; không dừng ngẫu nhiên các tiến trình Python khác.
- 0event: kiểm cửa sổ/thời gian/index/agent; không tự suy tấn công bị bỏ sót.
- `insufficient_context`: xem trường bị chặn và tiêu chí ca; chỉ thêm văn bản sau khi xem lại tại máy.

## Đổi máy / backup

Clone repo trên máy mới. Đăng nhập Codex và cấu hình lại CA/Indexer/mật khẩu trên máy đó. Không chép auth.json hoặc key vào Git.

Nếu cần chuyển lịch sử, dừng NEXUS trước khi sao lưu toàn bộ `data/private/app/` bằng kênh riêng. Thư mục có SQLite, HMACkey, request/response và có thể chứa thông tin nội bộ. Giữ HMACkey nếu muốn đối chiếu định danh cũ; bảo vệ backup theo quyền truy cập của máy. SourceZIP/publicrepo không thay thế backup này.
