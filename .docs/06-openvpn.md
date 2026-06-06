# 06 — OpenVPN (driver tương lai, Tier 1)

> KHÔNG dùng PPP. Giao thức riêng: control channel (TLS) + data channel, ghép trên 1 socket UDP/TCP, demux theo byte đầu.

## Header gói
- 1 byte đầu: **5-bit opcode** (cao) + **3-bit key_id** (thấp; tới 8 phiên key chồng nhau cho rekey liền mạch).
- Opcode: 1=HARD_RESET_CLIENT_V1, 2=HARD_RESET_SERVER_V1, 3=SOFT_RESET_V1, 4=P_CONTROL_V1, 5=P_ACK_V1, 6=P_DATA_V1, 7=HARD_RESET_CLIENT_V2, 8=HARD_RESET_SERVER_V2, 9=P_DATA_V2, 10=HARD_RESET_CLIENT_V3, 11=P_CONTROL_WKC_V1.
- **TCP:** mỗi gói có prefix **16-bit big-endian length** (vì TCP không có ranh giới). **UDP:** 1 gói = 1 datagram.

## Control channel + reliability layer
- Control packets (`P_CONTROL_*`, `P_ACK_*`): **64-bit session-id** + **32-bit packet-id** (bắt đầu 0, độc lập mỗi chiều).
- ACK qua `P_ACK_V1` (tới **8** packet-id) hoặc piggyback trên `P_CONTROL_V1` (tới **4**). Gói chưa ack → retransmit.
- **TLS chạy BÊN TRONG** reliability layer: feed TLS record qua các `P_CONTROL` (wrap `SslStream` lên một custom Stream làm framing/reliability).
- Data channel: KHÔNG tin cậy (best-effort như IP), packet-id riêng → anti-replay.

## tun (L3) vs tap (L2)
- **tun:** payload `P_DATA` = **gói IP thô** → cắm `IPacketChannel`. Ưu tiên làm trước.
- **tap:** payload = **khung Ethernet** → qua `EthernetAdapter`. Ít phổ biến (mobile apps không hỗ trợ).
- Wire bytes giống nhau; chỉ payload khác.

## Cấp IP / routes / DNS
- Qua **PUSH_REQUEST → PUSH_REPLY** (control-channel directives), KHÔNG phải DHCP (ở tun).
- Directive: `ifconfig`/`ifconfig-push` (IP), `route`/`redirect-gateway`, `dhcp-option DNS/DOMAIN/WINS`, `peer-id`, `cipher`.
- → parse PUSH_REPLY vào `TunnelConfig{AssignedIP,Routes,Dns,...}`. (tap mode có thể DHCP thật.)

## Crypto
- **Control:** TLS (1.0–1.3). Optional `tls-auth` (HMAC) / `tls-crypt` (AES-256-CTR + HMAC-SHA256) bảo vệ control + giấu cert.
- **Data AEAD (mặc định):** AES-256-GCM / AES-128-GCM / CHACHA20-POLY1305. Nonce = packet-id + implicit IV (từ key material); AAD = opcode|key_id|peer_id|packet_id.
- **Data CBC (legacy):** AES-CBC + HMAC. Layout: HMAC | IV | enc(packet-id+payload).
- **NCP:** thoả thuận cipher qua `IV_*` peer-info trong TLS handshake (`IV_CIPHERS=...`).
- **Key derivation (key-method 2):** dùng **TLS_PRF kiểu TLS-1.0 (MD5+SHA1)** — .NET KHÔNG có sẵn, phải tự viết. Label "OpenVPN master secret" / "OpenVPN key expansion".

## Khả thi C#
- TLS = `SslStream`; AES-GCM/CBC/HMAC/ChaCha20Poly1305 có trong BCL (net5+). Phần khó: reliability/handshake state machine, wrap SslStream qua P_CONTROL, byte-exact GCM nonce/AAD, TLS_PRF MD5+SHA1. Không cần native.
- ⚠️ Byte-exact nonce/AAD và epoch-key format khác nhau giữa version → đọc `crypto.c`/`ssl_pkt.c` trước khi code.

## Nguồn
- Wire protocol (WIP RFC): https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html
- Network protocol doxygen: https://build.openvpn.net/doxygen/network_protocol.html
- Cipher negotiation: https://github.com/OpenVPN/openvpn/blob/master/doc/man-sections/cipher-negotiation.rst
