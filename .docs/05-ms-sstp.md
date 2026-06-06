# 05 — MS-SSTP (driver Tier 0, dễ nhất — pure userspace)

## Chồng giao thức

```
userspace IP packets
   │  PPP (LCP → MS-CHAPv2/EAP → IPCP)
   │  SSTP (control + data packets, header 4 byte)
   │  HTTPS (SSTP_DUPLEX_POST) over TLS
   └─ SslStream / TcpClient → server:443
```

Không vướng ràng buộc raw-IP/đặc quyền — chỉ TLS/TCP 443. → **làm trước (M4) để validate trục chung**.

## Handshake (theo [MS-SSTP])

1. TCP connect `server:443` + TLS handshake (`SslStream`, có thể client cert).
2. **HTTP layer:** gửi `SSTP_DUPLEX_POST` tới URI:
   ```
   /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/
   ```
   với Content-Length rất lớn → biến HTTPS stream thành ống duplex.
3. **SSTP control:** `SSTP_MSG_CALL_CONNECT_REQUEST` (Encapsulated Protocol = PPP) → `..._ACK` → bắt đầu PPP → `..._CONNECTED` (kèm Crypto Binding).
4. **PPP:** LCP → auth → IPCP (cấp IP/DNS).
5. **Crypto Binding (chống MITM):** hash của server TLS cert (CMAC/HMAC) gắn vào keying PPP.

## Định dạng gói SSTP (header 4 byte)

```
byte0: Version  (MUST = 0x10)
byte1: bit7..1 Reserved(=0) ; bit0 C  (0=data, 1=control)
byte2-3: R(4-bit reserved) + Length(12-bit) = tổng độ dài gói
```
- **C=0 (data):** payload = **1 khung PPP** (length−4 byte).
- **C=1 (control):** payload = `SSTP_MSG_*` + attributes.
- **KHÔNG** có session/tunnel/call ID → 1 PPP/1 connection (xem `03`).
- **Length 12-bit → gói tối đa 4095 byte → PPP payload ≤ 4091 byte.** ⇒ đặt MRU/MTU phù hợp.

## PPP cho SSTP

- **Framing (đã verify thực tế với VPN Gate):** SSTP data packet mang **PPP THÔ** — **1 PPP frame / 1 data packet**, delineate bằng **trường Length của SSTP**, KHÔNG HDLC byte-stuffing/FCS. (Trước đó phỏng đoán HDLC theo sstp-client là SAI; test thật cho thấy gửi HDLC → server bỏ qua, raw → server trả lời.) HdlcFramer/Decoder chỉ dùng cho L2TP-stream khác, không cho SSTP.
- Auth: MS-CHAPv2 (hoặc EAP). IP qua IPCP (xem `03`/`04`).
- **Đã chạy thật:** `vpn/vpn` @ public-vpn-227.opengw.net:443 → LCP → MS-CHAPv2 → CHAP Success. Crypto binding (Call Connected) cần cho bước IPCP→IP.

## Lưu ý triển khai
- `SslStream` xử lý TLS; bên trên là `IByteStreamTransport` cho `PppEngine`.
- Keepalive: SSTP control `SSTP_MSG_ECHO_REQUEST/RESPONSE` + LCP echo.
- `ClientHTTPCookie` chỉ là token reconnect, KHÔNG phải multiplex.

## Nguồn ([MS-SSTP] open spec)
- Overview: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/70adc1df-c4fe-4b02-8872-f1d8b9ad806a
- SSTP Packet (2.2.1): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/2991892f-fefc-4129-adac-cd6a5d04bb48
- Messages: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/9edb5e01-08a6-4475-b1bf-6fe46a10aa0f

## Lab test
- Windows RRAS (SSTP), SoftEther (SSTP clone), MikroTik.
