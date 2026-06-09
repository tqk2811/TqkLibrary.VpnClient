# TqkLibrary.Vpn — hướng dẫn dự án

- **Luôn cập nhật `.docs/` mỗi khi chỉnh sửa code.** Sau mỗi lần thêm/sửa tính năng hoặc đổi hành vi (không chỉ commit cuối):
  - Cập nhật [`.docs/10-codebase-architecture-and-flow.md`](.docs/10-codebase-architecture-and-flow.md) — tài liệu **as-built, phải khớp code**: bảng module (§5), luồng kết nối/vòng đời (§6), data plane (§8), trạng thái hiện thực (§9), và mọi link `file:line`.
  - Cập nhật [`.docs/11-todo-roadmap.md`](.docs/11-todo-roadmap.md) — đánh dấu mục đã xong / phần còn lại. Và cập nhật README*.md ở các project đã sửa.
  - `.docs/00`–`09` là **design-intent**, giữ nguyên; sai lệch giữa design ↔ code thực tế ghi vào bảng **"Khác biệt so với design docs"** ở cuối file 10 (đừng viết lại 00–09 cho khớp code).
 
- Build phải xanh cả `netstandard2.0` + `net8.0`; tránh `record`/`init` (netstandard2.0 không có `IsExternalInit`).
- Test live phụ thuộc VPN Gate đánh dấu `[Trait("Category","Integration")]` — chạy offline bằng `--filter "Category!=Integration"`.
- Các quy tắc chung (link code, tiếng Việt, git, C#) theo `~/.claude/CLAUDE.md`, `~/.claude/git.md`, `~/.claude/csharp.md`.
