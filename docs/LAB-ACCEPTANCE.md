# Kiểm thử chấp nhận trên lab

Bản này chuẩn bị phần mềm để nhóm tự thử. Chưa chạy tấn công hoặc cài candidate lên VM trong quá trình phát hành.

## Trước khi thử

- Chốt máy/agent/địa chỉ thuộc quyền kiểm soát và thời gian thử; snapshot VM trước thay rule.
- Kiểm manager/indexer/dashboard, agentWindows và nguồn log mong đợi. Sysmon phải được kiểm riêng nếu dùng event Sysmon.
- Đồng bộ thời gian, ghi cửa sổUTC, phiên bảnWazuh và cấu hìnhdecoder/rule. Kiểm NEXUS đọc được sự kiện mới, không chỉ sự kiện cũ.
- Tạo ca với tiêu chí thực thi thành công và tiêu chí alert phù hợp **trước** khi chạy. Chia development và held-out trước tinh chỉnh.
- Không dùng tổngalert, Wazuhlevel hoặc nhãnAI làm groundtruth.

## Thứ tự thử

1. **Benign baseline:** ghi hoạt động bình thường, bằng chứng thực thi và telemetry tương ứng. Xác minh không có kết luận quá mức từ AI.
2. **Mô phỏng có kiểm soát:** chạy kịch bản do nhóm chọn trong phạm vi lab; ghi bằng chứng thực thi, source_log/manager_log và alert. Dừng nếu ngoài phạm vi.
3. **Thu thập:** đọc đúng agent/cửa sổ và xem cờ truncated. Nếu bị cắt, thu hẹp cửa sổ hoặc lưu bằng chứng bổ sung; polling không bảo đảm lấy hết event.
4. **Triage:** chọn event liên quan, xempreview, duyệtgửi. Đối chiếuErefs với eventgốc; ghi các suy luận sai/thiếu củaAI, không chỉ câu trả lời hay.
5. **Đánh giá baseline:** detected, log_without_alert, no_log, inconclusive, execution_failed hoặcblocked theo bằng chứng. Runlỗi/thiếu bằng chứng không được tính thành Wazuh bỏ sót.
6. **Candidate development:** nếu có log mà thiếu alert phù hợp, đề xuấtXML với tiêu chí rõ. Đọc XML và phạm vi matching, lưu bản mới cósha. Không nạp trực tiếpoutputmodel vàoWazuh.
7. **Kiểm candidate:** dùng bundle/helper trênUbuntu. Stage kiểm ID và cấu hình; logtest một dòng phải khớp rule/level/decoder đã định. Làm attack, benign và regression riêng; đọc report private. Helper không tự mô phỏng/replay.
8. **Kích hoạt lab:** chỉ sau review và ba loại check pass mới dùng activate. Bản này chưa có bằng chứng thực nghiệm rằng activate/rollback chạy được trên từng cấu hình Wazuh; kiểm trạng thái manager và sẵn sàng rollback.
9. **Thử lại và held-out:** giữ bằng chứng trước/sau với cùng điều kiện, sau đó dùng ca held-out chưa tham gia chỉnh rule. Không sửa candidate theo kết quả held-out rồi vẫn gọi đó là held-out.

## Ghi kết quả

Mỗi run cần ID ca, development/held-out, baseline/tuned, phiên bản Wazuh, hash candidate, thời gianUTC, agent, bằng chứng thực thi, log/alert và trạng thái thu thập. Bằng chứng lab/fixture phải gán đúng nguồn. Không chỉnh lịch sử AI để biến ý kiếnmodel thành bằng chứng thực thi.

Biểu mẫu Ca thử/Bằng chứng/Lần chạy/Kiểm thử rule trongapp là hồ sơ do người dùng nhập. Check thủ công không tự trở thành runner-verified. Không báo cáo tỷ lệ cảnh báo giả khi chưa có tập benign và định nghĩa đơn vị đo. Coverage trên bộ kỹ thuật đã chọn không đại diện mọi tấn công.

## Tiêu chí hoàn tất nghiệm thu

- Có dữ liệu mới từ nguồn dự kiến và thời gian đúng; các lỗi collection được ghi riêng.
- Triage có căn cứ hoặc nêu thiếu dữ liệu, không thực thi chỉ dẫn tronglog.
- Candidate gắn development/evidence, validateXMLpass, logtest positive/benign/regression và thửrestoremanager.
- Kịch bản held-out được giữ độc lập. Chất lượng, độ trễ và nhận định sai được ghi bằng số liệu đo thực.

Nếu chưa đạt, ghi lỗi và sửa source/rule; không tuyên bố đạt vì unit tests hoặc một lần replay thành công.


## Ghi run held-out với rule đã phát triển

Candidate phải được tạo từ ca development. Để đánh giá trên một ca held-out khác, chọn ca held-out ở mục Lần chạy, chọn phase=tuned và candidate development đã chốt. Ở đây tuned có nghĩa dùng phiên bản rule đã phát triển, không có nghĩa được tinh chỉnh trên dữ liệu held-out. Run giữ candidate ID, SHA-256 và ca development nguồn; candidate không bị sửa. Ca development vẫn phải dùng candidate của chính ca đó. Baseline không gắn candidate; tạo candidate mới/child từ held-out vẫn bị chặn.
