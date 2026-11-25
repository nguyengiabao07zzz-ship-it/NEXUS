# Privacy fixtures

`wazuh_sysmon_process_create.synthetic.json` là **dữ liệu giả lập**, mô phỏng cấu trúc bao alert Wazuh và Sysmon Event1 để kiểm tra policy hiện tại. RuleID/level/metadata không phải output đã xác minh trên Wazuh4.14; không phải log thu từ lab, không xác nhận timestamp format trong deployment thật. Canary, IP TEST-NET và domain `.invalid` đều dùng cho test. CommandLine là chuỗi dữ liệu, không được thực thi.

Test R2-02 ghi rõ cả những trường đang giữ và đang mất. Test pass không nghĩa preview đủ cho LLM hoặc an toàn với mọi dữ liệu. Policy không được nới trong vòng này; lấy alert thật và chọn trường phục vụ detection là việc chờ ca tay.
