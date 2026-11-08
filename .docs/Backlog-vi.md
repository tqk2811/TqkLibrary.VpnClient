# Backlog

Việc còn treo và việc nên làm của thư viện. Xử lý xong mục nào thì xoá mục đó trong cùng commit với bản sửa.

Phần lớn mục chuyển từ backlog của app ProxyDivert ngày 2026-11-08. Mục mang mã C đến từ đợt rà soát ngày 2026-09-08 (C = lỗi VpnClient phát hiện qua cách app dùng thư viện). Mức `Cao`/`Vừa`/`Thấp` theo nhãn trong tiêu đề. Đường dẫn `src/ProxyDivert.*` là của repo app ProxyDivert (repo cha, nhúng thư viện này làm submodule); đường dẫn khác tính từ gốc repo này.

### [Thấp] VpnClient: TcpConnection gọi SendIp khi đang giữ `_sync`

- **Vấn đề:** `EmitSegment` gọi `_sendIp` trong các khối `lock (_sync)`, và egress của `TcpIpStack` giờ ghi channel ngay trên thread đó khi rảnh. Channel nào raise `InboundIpPacket` đồng bộ bên trong `WriteIpPacketAsync` (vd một switch nội bộ nối hai `VirtualHost`) sẽ làm gói trả lời vào lại connection giữa lúc đang cập nhật, hoặc deadlock hai connection. Hiện chưa channel nào trong repo làm vậy; hợp đồng đã ghi ở doc `IPacketChannel.WriteIpPacketAsync`.
- **Vị trí:** `src/TqkLibrary.VpnClient.IpStack/Tcp/TcpConnection.cs` (`EmitSegment`), `src/TqkLibrary.VpnClient.Ethernet/VirtualHost.cs` (raise inbound từ switch).
- **Vì sao:** cách chắc nhất là TcpConnection gom gói ra trong lock và chỉ gửi sau khi nhả `_sync`; hoặc thêm Debug.Assert/test chặn channel giao inbound đồng bộ.
- **Ngày ghi:** 2026-10-29.

### [Thấp] VpnClient: BouncyCastle TLS/DTLS chạy chế độ chặn trên thread riêng

- **Vấn đề:** `BouncyCastleTlsByteStream` và `DtlsDatagramTransport` giữ một thread đọc riêng (TLS thêm một thread ghi) cho mỗi tunnel vì dùng API chặn của BouncyCastle; thread nhận DTLS poll 250 ms để thấy dispose. Bên trong `dtls.Receive`, BouncyCastle có thể tự gửi (alert, retransmit) mà không qua `_sendLock` (có từ trước).
- **Vị trí:** `src/TqkLibrary.VpnClient.Transport.Tls/BouncyCastleTlsByteStream.cs`, `src/TqkLibrary.VpnClient.Transport.Dtls/DtlsDatagramTransport.cs`.
- **Vì sao:** chế độ không chặn (`TlsClientProtocol()` + `OfferInput`/`ReadOutput`) trên socket async bỏ được cả thread lẫn semaphore và poll; công lớn (viết lại handshake + đường dữ liệu, cần test với server thật).
- **Ngày ghi:** 2026-10-29.

### [Thấp] VpnClient: ARP thất bại không được cache

- **Vấn đề:** gateway chết thì mỗi gói ra chờ trọn timeout ARP (khoảng 3 s: RequestTimeout 1 s × 3 lần) trong `VirtualHost.WriteIpPacketAsync`, giữ cả hàng egress của stack; queue đầy thì phần dư bị bỏ (có đếm, có log Warning).
- **Vị trí:** `src/TqkLibrary.VpnClient.Ethernet/VirtualHost.cs`, `ArpResolver`.
- **Vì sao:** cache âm ngắn (vài giây) để gói sau báo lỗi ngay thay vì chờ lại.
- **Ngày ghi:** 2026-10-29.

### [Thấp] VpnClient: các chỗ còn bọc lệnh chặn trong `Task.Run`

- **Vấn đề:** cùng kiểu async-over-sync (giữ một thread pool thread trong lúc chờ) còn ở `OpenVpnBouncyCastleControlTls`, `SshClient`, `PptpGreChannel` và các channel IpEncap. Khi thread pool bị nghẽn thì các đường này chậm hoặc đứng.
- **Vị trí:** `src/TqkLibrary.VpnClient.OpenVpn/OpenVpnBouncyCastleControlTls.cs`, `TqkLibrary.VpnClient.Ssh/SshClient.cs`, `TqkLibrary.VpnClient.Pptp/Gre/PptpGreChannel.cs`, `TqkLibrary.VpnClient.IpEncap/*Channel.cs` (grep `Task.Run`).
- **Vì sao:** làm theo khuôn đã dùng cho TLS/DTLS/RawIp (thread riêng cho vòng đọc chặn, hoặc API socket async thật).
- **Ngày ghi:** 2026-10-29.

### C9. Cửa sổ nhận của `TcpConnection` cứng 65535, không back-pressure (Vừa)

- **Vấn đề:** cửa sổ nhận vẫn quảng cáo 65535 dù không ai đọc `_recvQueue`, nên server cứ đẩy, hàng đợi nhận phình theo tốc độ server thay vì tốc độ tiến trình đọc. (Hai khuyết điểm kia của C1 cũ, `Abort()` → RST và timer FIN-WAIT-2, đã sửa.)
- **Vị trí:** [TcpConnection.cs:37](../src/TqkLibrary.VpnClient.IpStack/Tcp/TcpConnection.cs#L37) (`const ushort ReceiveWindow = 65535`), dùng ở [:463](../src/TqkLibrary.VpnClient.IpStack/Tcp/TcpConnection.cs#L463) và [:952](../src/TqkLibrary.VpnClient.IpStack/Tcp/TcpConnection.cs#L952); `_recvQueue`.
- **Cách sửa:** cửa sổ = `max(0, cap − _recvQueue.Count)` và gửi window update khi tiến trình đọc; commit trong submodule VpnClient, kèm test.
- **Ngày ghi:** 2026-09-11.

### C11. Huỷ giữa lúc dial in-tunnel để lại kết nối nửa mở trong stack (Vừa)

- **Vấn đề:** `WhenAny(Connected, Delay(∞, ct))` rồi `ThrowIfCancellationRequested()` ném OCE mà không `Abort()`/gỡ entry; `connection.Closed` chỉ chạy khi SYN retransmit bỏ cuộc, nên cổng + `TcpConnection` sống tới lúc đó. Mỗi lần Save đổi route (engine cancel các kết nối đang dựng) là một loạt.
- **Vị trí:** [TcpIpStack.cs:109-110](../src/TqkLibrary.VpnClient.IpStack/TcpIpStack.cs#L109-L110).
- **Cách sửa:** `catch (OperationCanceledException) { connection.Abort(); throw; }` (`Closed` sẽ gỡ entry); commit trong submodule VpnClient, kèm test.
- **Ngày ghi:** 2026-09-11.
