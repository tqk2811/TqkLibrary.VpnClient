# 07 — SoftEther VPN native (driver tương lai, Tier 0/L2)

> "Ethernet over HTTPS". KHÔNG dùng PPP, transport **khung Ethernet** (L2). Là driver L2 điển hình → đi qua `EthernetAdapter`.
> ⚠️ Source GPL/AGPL — **KHÔNG copy code**; re-implement từ hành vi. Watermark là *data* tái tạo byte-exact.

## Wire framing: PACK
- Mọi control/RPC = **PACK** (binary typed key-value, KHÔNG phải JSON). `PACK` = LIST các `ELEMENT`; mỗi ELEMENT có name (≤63 ký tự), type, mảng `VALUE`.
- VALUE type: `VALUE_INT=0`, `VALUE_DATA=1` (raw bytes), `VALUE_STR=2` (ANSI), `VALUE_UNISTR=3` (Unicode), `VALUE_INT64=4`.
- Big-endian length-prefixed (`BufFromPack`/`PackFromBuf`). Limit khác nhau 32-bit vs 64-bit build.

## Handshake
1. TCP connect (443/992/5555) + TLS handshake.
2. **Watermark:** POST `POST /vpnsvc/connect.cgi HTTP/1.1`, body = blob watermark cố định (`src/Cedar/Watermark.c`) + random padding. (Server chỉ cần đúng dòng POST.)
3. **Hello:** server trả PACK `hello`, `version`, `build`, `random` (20 byte challenge).
4. **Auth:** client POST PACK `method=login`, `hubname`, `username`, `authtype`, credential, + session params (`max_connection`, `use_encrypt`, `use_compress`, `half_connection`, `unique_id`...).
5. **Welcome:** server trả `session_key` (20 byte, **handle** không phải khoá crypto), `session_key_32`, policy `policy:*`.

## Auth password — SHA-0 (KHÔNG phải SHA-1)
- `HashPassword = Sha0(password || UPPER(username))`.
- on-wire `SecurePassword = Sha0(hashed[20] || server_random[20])`.
- → cần tự viết **SHA-0** (= SHA-1 bỏ phép rotate trong message schedule, ~30 dòng). Password gốc không qua wire.

## L2 / SecureNAT (đúng kịch bản userspace, không TUN/TAP)
- Virtual Hub = switch học MAC (FDB), forward theo dest-MAC. Client = NIC ảo trên segment → thấy ARP/broadcast/DHCP.
- **SecureNAT** chạy **user mode** (stack TCP/IP riêng): Virtual DHCP (pool mặc định 192.168.30.10–.200, gw .1) + Virtual NAT. → client chỉ cần **ARP responder + DHCP client** trên L2 để lấy IP.
- ⇒ Map vào `EthernetAdapter` của ta: VirtualHost gửi DHCP DISCOVER (Ethernet/UDP frame) → nhận lease → chạy IpStack trên IP đó.

## Multi-host & multi-connection
- **Multi-MAC:** ở Bridge/Router mode + policy Hub cho phép ("Maximum Number of MAC Addresses" default unlimited, 1–65535; chặn khi BOTH Deny-Bridge + Deny-Routing). → nhiều VirtualHost trên 1 session.
- **1–32 parallel TCP / 1 session logic** (throughput): connection phụ reattach bằng `additional_connect` + `session_key` (server `GetSessionFromKey`). Optional `half_connection` (nửa up, nửa down). → model "1 session sở hữu N socket + M MAC".
- Data frame: length-prefixed, optional deflate (magic `0xDEADBEEFCAFEFACE`), optional RC4 trên TLS. Keep-alive = chuỗi `"Internet Connection Keep Alive Packet"`.

## Khả thi C#
- Pure managed: `SslStream` + tự viết **SHA-0**, **RC4**, **PACK codec**. Tham chiếu: `march1993/go-softether` (PoC password-only), `pysoftether` (PACK). Không cần OpenSSL/native.
- ⚠️ Đọc trực tiếp `Connection.c`/`Protocol.c`/`Session.c` cho framing/compression/half_connection trước khi code.

## Nguồn
- Spec: https://www.softether.org/3-spec
- Comm protocol: https://www.softether.org/4-docs/1-manual/2._SoftEther_VPN_Essential_Architecture/2.1_VPN_Communication_Protocol
- SecureNAT/DHCP/NAT: https://www.softether.org/4-docs/1-manual/3/3.7
- Source: https://github.com/SoftEtherVPN/SoftEtherVPN (Pack.h, Account.c, Sam.c)
- go-softether: https://github.com/march1993/go-softether
