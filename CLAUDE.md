# TqkLibrary.Vpn — hướng dẫn dự án

- **Luôn cập nhật `.docs/` mỗi khi chỉnh sửa code.** Sau mỗi lần thêm/sửa tính năng hoặc đổi hành vi (không chỉ commit cuối):
  - Cập nhật [`.docs/10-codebase-architecture-and-flow.md`](.docs/10-codebase-architecture-and-flow.md) — tài liệu **as-built, phải khớp code**: bảng module (§5), luồng kết nối/vòng đời (§6), data plane (§8), trạng thái hiện thực (§9), và mọi link `file:line`.
  - Cập nhật [`.docs/11-todo-roadmap.md`](.docs/11-todo-roadmap.md) — roadmap **chỉ chứa việc chưa làm**: mục đã hoàn thành thì **xóa khỏi roadmap** (không đánh dấu `[x]`/strikethrough/✅); thành quả as-built ghi nhận ở file 10 + README project tương ứng.
  - `.docs/00`–`09` là **design-intent**, giữ nguyên; sai lệch giữa design ↔ code thực tế ghi vào bảng **"Khác biệt so với design docs"** ở cuối file 10 (đừng viết lại 00–09 cho khớp code).

- **Luôn cập nhật `src/TqkLibrary.Vpn*/README*.md` của project mỗi khi sửa đổi project chứa nó.** Mỗi project trong `src/` có một `README-vi.md` mô tả **as-built** (mục đích, vị trí kiến trúc, phụ thuộc/được-dùng-bởi, cấu trúc thư mục, bảng type, bảng chuẩn/RFC, luồng nội bộ, trạng thái & ghi chú). Khi thêm/sửa/xóa type, đổi hành vi, đổi `ProjectReference`/`PackageReference`, đổi target framework, hay dịch chuyển số dòng mà README link tới → **phải cập nhật README của (các) project bị ảnh hưởng cho khớp code**, theo `Quy tắc link code` (đường dẫn tương đối tính từ chính file README). README phải khớp code giống `.docs/10`.

- Build phải xanh cả `netstandard2.0` + `net8.0`. `record`/`init`/`required` **dùng được cả 2 TFM** nhờ package source-only **`TqkLibrary.CompilerServices`** (đã ref ở [`src/Directory.Build.props`](src/Directory.Build.props), chỉ netstandard2.0) biên dịch sẵn `IsExternalInit` + các attribute `required` vào assembly; net8.0 có sẵn trong BCL nên `#if` guard tự loại (package là no-op).
  - **Đừng cứng `#if NET8_0_OR_GREATER`**: tra cứu API/tính năng đó có sẵn từ .NET nào rồi rào theo phiên bản **thấp nhất** hỗ trợ — vd có từ net5 thì `#if NET5_0_OR_GREATER`, từ net6 thì `#if NET6_0_OR_GREATER`. Như vậy code dùng được trên nhiều TFM hơn, không khóa thừa lên net8.
- Test live phụ thuộc VPN Gate đánh dấu `[Trait("Category","Integration")]` — chạy offline bằng `--filter "Category!=Integration"`.
- **Hạn chế sử dụng hàm static**: ưu tiên instance method sau interface (dễ test/mock/DI, thay thế được trong test); chỉ dùng static cho pure function/codec không trạng thái.
- **Tái sử dụng tối đa, không viết lại tính năng có sẵn**: trước khi viết mới, tìm type/helper sẵn có trong solution (và BCL) để dùng lại; nếu gần khớp thì mở rộng type sẵn có thay vì nhân bản logic.
- Các quy tắc chung (link code, tiếng Việt, git, C#) theo `~/.claude/CLAUDE.md`, `~/.claude/git.md`, `~/.claude/csharp.md`.
