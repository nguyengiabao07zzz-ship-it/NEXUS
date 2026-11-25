# NEXUS release checkpoint — 25/11/2026

Status: lab evaluation build, not production certification.

Included: Indexer intake; local grouping/filter/priority; explicit reviewed-context AI preview; Codex ChatGPT/OpenAI API adapters; triage and development-only rule drafts; history; candidate bundle/helper; bounded local polling; startup diagnostics and guides.

Local validation before publication:108 tests pass; JS syntax and PowerShell parsing pass. UI checked on separate synthetic/mocked fixture. Two latest model smoke tests used synthetic JSON only. Live Wazuh stage/activation/rollback, attack replay and measured efficacy remain pending user lab evaluation. See docs/VALIDATION.md.

GitHub CI is configured for Windows/Linux and Python3.11/3.12. A configured workflow is not a passed run; consult Actions for remote results.

Source continues the team's LLM-in-Wazuh project. This public repository excludes internal project/competition/team files, old machine-specific notes and all private runtime data. It does not replace a private backup of development records.


## 25/11/2026 — Sửa hai lỗi được review trên da84d3e

Tái hiện lỗi trước sửa bằng fixture/HTTP nội bộ. Cho phép đánh giá candidate development bất biến trên held-out, pin candidate hash/ca nguồn; vẫn chặn phát triển rule từ held-out và dùng candidate khác ca cho development. Tách grouping event đã parse khỏi parser file1 MB để Indexer chấp nhận phản hồi hợp lệ tới2 MB, không serialize lại gây phình UTF-8. Thêm10 regression tests; toàn bộ118tests đạt tại máy. Không gọi AI, không gửi log lab hoặc chạy lệnh Wazuh trong lượt sửa. Bổ sung hướng dẫn phân biệt tuned-evaluation và tuning; CI của commit mới được kiểm sau push.
