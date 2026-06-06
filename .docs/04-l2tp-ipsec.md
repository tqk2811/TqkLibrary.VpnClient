# 04 — L2TP/IPsec (driver Tier 0)

## Chồng giao thức

```
userspace IP packets
   │  PPP (LCP → MS-CHAPv2/PAP/CHAP → IPCP)        ← lấy IP, DNS
   │  L2TP (control SCCRQ.. + data, Tunnel/Session ID)
   │  ESP (transport mode, mã hoá L2TP/UDP 1701)
   │  UDP/4500 NAT-T (RFC 3948)                    ← đường userspace
   │  IKEv2 (UDP/4500, PSK)                         ← thiết lập IPsec SA
   └─ UDP socket cổng nguồn ephemeral
```

## Lộ trình thiết lập (M5–M6)

1. **IKEv2 (RFC 7296), PSK:**
   - `IKE_SA_INIT`: trao đổi SA proposal + KE (DH group 14) + Nonce + NAT-D payload (báo "có NAT" → ép NAT-T).
   - `IKE_AUTH`: xác thực PSK, thiết lập **CHILD_SA** cho ESP transport mode bảo vệ UDP/1701.
   - v1 chỉ: **PSK**, 1 transform cố định (AES-CBC-256 + HMAC-SHA256 + DH14 + ESP AES-CBC-256/HMAC-SHA256). Bỏ rekey/MOBIKE/fragmentation/EAP/cert.
2. **ESP (RFC 4303) transport mode:** bọc gói UDP/1701 (L2TP). SPI demux, sequence, anti-replay window, padding. Chạy trong **UDP/4500** (RFC 3948): 4 byte 0x00000000 Non-ESP-Marker phân biệt IKE vs ESP.
3. **L2TP (RFC 2661):** control 3-way `SCCRQ→SCCRP→SCCCN` mở tunnel; `ICRQ→ICRP→ICCN` mở session; data carry PPP. Header có Tunnel ID + Session ID.
4. **PPP:** chạy LCP → auth (MS-CHAPv2) → IPCP. IPCP cấp IP + DNS (xem `03`).

## Cổng & NAT-T (ràng buộc userspace — xem `01`)

- **KHÔNG bind UDP 500/4500 local** (tránh IKEEXT của Windows). Dùng **cổng nguồn ephemeral**, gửi tới `server:500` rồi float `server:4500`.
- **Ép NAT-T** (client tự xưng sau NAT qua NAT-D hash mismatch) → ESP đi trong UDP/4500, không cần raw proto-50.
- Rủi ro: server từ chối forced-NAT-T → fallback native-ESP (raw, elevate).

## PPP cho L2TP

- **Framing:** packet-mode (UDP đã có ranh giới gói — KHÔNG HDLC byte-stuffing). Protocol field: 0x0021 IPv4, 0xC021 LCP, 0xC223 CHAP/MS-CHAPv2, 0x8021 IPCP.
- **LCP:** thoả thuận MRU, Auth-Protocol (MS-CHAPv2 = 0xC223 + algorithm 0x81), Magic-Number, ACCM.
- **MS-CHAPv2 (RFC 2759):** server gửi Challenge → client tính NT-Response = dùng **MD4(password unicode)** làm NT-hash, **DES** 3 lần trên Challenge-Hash; gửi lại + Peer-Challenge; verify Authenticator-Response. (Crypto: xem `08`.)
- **IPCP:** xin IP (option 3 = 0.0.0.0) + DNS (RFC 1877 option 129/131).

## Tham số/transform v1 (cố định, thu hẹp phạm vi)

| Lớp | Thuật toán |
|---|---|
| IKEv2 auth | PSK |
| IKEv2 DH | group 14 (MODP-2048) |
| IKEv2 enc/integ/prf | AES-CBC-256 / HMAC-SHA256-128 / PRF-HMAC-SHA256 |
| ESP enc/integ | AES-CBC-256 / HMAC-SHA256-128 |
| PPP auth | MS-CHAPv2 (PAP/CHAP fallback) |

## RFC tham chiếu
- L2TPv2: RFC 2661 — https://www.rfc-editor.org/rfc/rfc2661.txt
- IKEv2: RFC 7296 — https://datatracker.ietf.org/doc/html/rfc7296
- ESP: RFC 4303 — https://datatracker.ietf.org/doc/html/rfc4303
- UDP-encap ESP (NAT-T): RFC 3948 — https://datatracker.ietf.org/doc/html/rfc3948
- IPCP: RFC 1332 — https://www.rfc-editor.org/rfc/rfc1332.html
- IPCP DNS: RFC 1877 — https://datatracker.ietf.org/doc/html/rfc1877
- MS-CHAPv2: RFC 2759 — https://datatracker.ietf.org/doc/html/rfc2759
- PPP: RFC 1661 — https://www.rfc-editor.org/rfc/rfc1661.html ; HDLC framing RFC 1662

## Lab test
- strongSwan + xl2tpd (Docker), Windows RRAS, SoftEther L2TP/IPsec server. Wireshark đối chiếu IKE/ESP payload.
