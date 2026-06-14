# TqkLibrary.VpnClient.OpenVpn

Thư viện **protocol OpenVPN** thuần .NET (tương thích OpenVPN community server) — **không dùng PPP**. Control channel (TLS) + data channel ghép trên một socket UDP/TCP, demux theo byte opcode đầu. Đây là project protocol-level cho driver **V.2** (đang xây theo phase, xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.2).

> **Trạng thái:** **V2.a reliability-layer + config/.ovpn + V2.b TLS-in-control + V2.c tls-auth/tls-crypt + V2.d data channel AEAD xong**. Đã có: (1) codec gói control (opcode/key-id + session-id + ACK array + packet-id + payload); (2) reliability state machine — send window (gán packet-id + retransmit/backoff theo clock inject) + receive window (dedup + in-order delivery cho TLS + theo dõi ACK); (3) **`OpenVpnProfile` (config lập trình driver tiêu thụ) + `OpenVpnConfigParser` đọc `.ovpn`** (cert/key inline → PEM, dạng path → giữ đường dẫn cho caller; không I/O); (4) **`OpenVpnControlChannel` (client)** — ráp 2 window + codec + session-id + transport `IOpenVpnTransport`, làm reset HARD_RESET_CLIENT_V2 ⇄ HARD_RESET_SERVER_V2 rồi chạy `SslStream` thật trên `OpenVpnTlsBridgeStream` in-memory (TLS **bên trong** reliability layer); (5) **`IOpenVpnControlWrap`** — bọc/giải-bọc control packet: `OpenVpnTlsAuthWrap` (`--tls-auth` HMAC) + `OpenVpnTlsCryptWrap` (`--tls-crypt` HMAC + AES-256-CTR) trên `OpenVpnStaticKey` (`ta.key` 2048-bit), opt-in ở ctor channel; (6) **key-method-2 + data channel AEAD** — `OpenVpnKeyNegotiation` trao đổi key_source2 trên `TlsStream`, `OpenVpnKeyMethod2`/`Tls1Prf` suy khóa, `OpenVpnDataChannel` gói **P_DATA_V2 + AES-256-GCM** (`AesGcmCipher`) + anti-replay 64-gói. **Chưa**: PUSH_REPLY/keepalive (V2.e), NCP (V2.f), `tls-ekm` (chờ F.5), transport TCP/tap (V2.g); **direction key + interop chờ lab Q.1**.

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [Ipsec](../TqkLibrary.VpnClient.Ipsec)/[L2tp](../TqkLibrary.VpnClient.L2tp)/[Ppp](../TqkLibrary.VpnClient.Ppp)): các khối giao thức thuần, **không** I/O socket — driver `Drivers.OpenVpn` (V.2, chưa có) sẽ lắp ráp thành tunnel sống. Reliability layer của OpenVPN tương tự vai trò control-channel của [L2tp](../TqkLibrary.VpnClient.L2tp) (Ns/Nr + retransmit) nhưng dùng **packet-id 32-bit + ACK array** thay cho sequence 16-bit.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | (cho các phase sau: `IPacketChannel`, exceptions, `IHostResolver`) |
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | `AesCtr` (tls-crypt V2.c), `Tls1Prf` (key-method-2 V2.d), `AesGcmCipher` + `AntiReplayWindow` (data channel V2.d) |
| Được dùng bởi | `Drivers.OpenVpn` (V.2, **chưa có**) | driver lắp ráp control/data plane |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.OpenVpn/
├─ OpenVpnPacketCodec.cs            Codec gói control: opcode/key-id, session-id, ACK array, packet-id, payload
├─ OpenVpnControlChannel.cs        Control channel (client): reset + reliability + SslStream (TLS-in-control) — V2.b
├─ OpenVpnTlsBridgeStream.cs       Stream in-memory cho SslStream: write→fragment reliable, read←payload in-order
├─ IOpenVpnTransport.cs            Cổng gửi/nhận 1 gói OpenVPN (driver UDP/TCP impl; in-process pair cho test)
├─ IOpenVpnControlWrap.cs          Bọc/giải-bọc control packet trên dây (tls-auth/tls-crypt) — V2.c
├─ OpenVpnTlsAuthWrap.cs           --tls-auth: HMAC xác thực control packet (key theo OpenVpnKeyDirection)
├─ OpenVpnTlsCryptWrap.cs          --tls-crypt: HMAC-SHA256 + AES-256-CTR mã hóa control packet (hướng theo role)
├─ OpenVpnStaticKey.cs             Parse ta.key 2048-bit (key2: 2 bộ cipher[64]|hmac[64]) + slice theo hướng
├─ OpenVpnReliabilityOptions.cs    Chính sách retransmit (interval/backoff/cap) + window size
├─ OpenVpnReliableSendWindow.cs    Send half: gán packet-id, in-flight window, retransmit theo clock
├─ OpenVpnReliableReceiveWindow.cs Receive half: dedup + in-order delivery + theo dõi ACK
├─ DataChannel/
│  ├─ OpenVpnKeySource2.cs         Vật liệu random key-method-2 (pre-master 48 + 2×random 32; server bỏ pre-master)
│  ├─ OpenVpnKeyMethod2.cs         Build client msg + parse server reply + DeriveDataKeys (Tls1Prf → master → key2)
│  ├─ OpenVpnDataChannelKeys.cs    Khóa data plane mỗi chiều: cipher key 32 + implicit IV 8
│  ├─ OpenVpnKeyNegotiation.cs     Chạy trao đổi key-method-2 trên TlsStream → OpenVpnDataChannelKeys
│  └─ OpenVpnDataChannel.cs        Protect/TryUnprotect P_DATA_V2 + AES-256-GCM + anti-replay
├─ Config/
│  ├─ OpenVpnProfile.cs            Config lập trình (remote, proto, device, TLS material, cipher/auth, options)
│  ├─ OpenVpnConfigParser.cs       Parse text .ovpn → OpenVpnProfile (pure, không I/O)
│  ├─ OpenVpnRemote.cs             1 endpoint `remote host [port] [proto]`
│  └─ OpenVpnFileOrInline.cs       cert/key: inline PEM hoặc đường dẫn file
├─ Enums/
│  ├─ OpenVpnOpcode.cs             5-bit opcode (P_CONTROL/P_ACK/HARD_RESET/SOFT_RESET/P_DATA…)
│  ├─ OpenVpnKeyDirection.cs       Bidirectional / Normal / Inverse cho tls-auth (key-direction)
│  ├─ OpenVpnProtocol.cs           Udp / Tcp
│  └─ OpenVpnDeviceType.cs         Tun / Tap
└─ Models/
   └─ OpenVpnControlPacket.cs      Gói control đã decode (session-id, acks, remote-session-id, packet-id, payload)
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `OpenVpnOpcode` | enum 5-bit opcode (giá trị 1–11 theo wire protocol) | [Enums/OpenVpnOpcode.cs:8](Enums/OpenVpnOpcode.cs#L8) |
| `OpenVpnControlPacket` | model gói control đã decode; `IsAckOnly` cho P_ACK_V1 | [Models/OpenVpnControlPacket.cs:10](Models/OpenVpnControlPacket.cs#L10) |
| `OpenVpnPacketCodec` | static codec: `Header`/`ReadOpcode`/`ReadKeyId` pack byte đầu; `IsControlOpcode`; `EncodeControl`/`TryDecodeControl` | [OpenVpnPacketCodec.cs:17](OpenVpnPacketCodec.cs#L17) |
| `OpenVpnReliabilityOptions` | `Interval`/`BackoffMultiplier`/`MaxInterval`/`MaxRetransmits`/`WindowSize` + `IntervalFor(resends)` (mirror `L2tpRetransmitOptions`) | [OpenVpnReliabilityOptions.cs:11](OpenVpnReliabilityOptions.cs#L11) |
| `OpenVpnReliableSendWindow` | `Queue`(gán id 0,1,2…) → `CollectDue(nowMs)` (gửi mới + retransmit hết interval, mark sent) → `Acknowledge(id/ids)`; `CanQueue`/`InFlight`/`IsExhausted(nowMs)` | [OpenVpnReliableSendWindow.cs:11](OpenVpnReliableSendWindow.cs#L11) |
| `OpenVpnReliableReceiveWindow` | `Offer(id,payload)` (dedup + buffer trong window) → `TryDeliver` (in-order cho TLS) → `TakeAcks(max)` (≤8 cho P_ACK / ≤4 piggyback); `NextExpectedId`/`PendingAcks` | [OpenVpnReliableReceiveWindow.cs:11](OpenVpnReliableReceiveWindow.cs#L11) |
| `IOpenVpnTransport` | cổng `SendAsync(packet)` + event `DatagramReceived` — 1 gói OpenVPN/đơn vị (driver UDP/TCP; in-process pair cho test) | [IOpenVpnTransport.cs:9](IOpenVpnTransport.cs#L9) |
| `OpenVpnControlChannel` | control channel client: ctor nhận `controlWrap?` (tls-auth/tls-crypt); `ConnectAsync(...)` reset + `SslStream` AuthenticateAsClient trên reliability layer; `NegotiateDataChannelKeysAsync(...)` chạy key-method-2 (V2.d); `LocalSessionId`/`RemoteSessionId`/`KeyId`/`TlsStream`/`RemoteCertificate` | [OpenVpnControlChannel.cs:21](OpenVpnControlChannel.cs#L21) |
| `OpenVpnTlsBridgeStream` *(internal)* | `Stream` in-memory cho SslStream: `WriteAsync`→fragment+gửi reliable (callback), `ReadAsync`←payload in-order qua `EnqueueInbound`; `CompleteInbound` đóng | [OpenVpnTlsBridgeStream.cs:15](OpenVpnTlsBridgeStream.cs#L15) |
| `IOpenVpnControlWrap` | seam bọc control packet trên dây: `Wrap(controlPacket)` / `TryUnwrap(wire, out controlPacket)` (byte→byte quanh codec; unwrap-fail ⇒ drop) | [IOpenVpnControlWrap.cs:12](IOpenVpnControlWrap.cs#L12) |
| `OpenVpnTlsAuthWrap` | `--tls-auth`: HMAC (mặc định SHA1) bọc — `op\|sid\|HMAC\|replay_id\|net_time\|body`, key out/in theo `OpenVpnKeyDirection`; `FixedTimeEquals` so tag | [OpenVpnTlsAuthWrap.cs:19](OpenVpnTlsAuthWrap.cs#L19) |
| `OpenVpnTlsCryptWrap` | `--tls-crypt`: HMAC-SHA256 + AES-256-CTR (`Crypto.AesCtr`, IV=tag[0..16]) — `op\|sid\|packet_id(8)\|tag(32)\|E(body)`, hướng cố định theo role | [OpenVpnTlsCryptWrap.cs:21](OpenVpnTlsCryptWrap.cs#L21) |
| `OpenVpnStaticKey` | parse `ta.key` 2048-bit (`Parse`/`FromBytes`); `key2` = 2 bộ `cipher[64]\|hmac[64]`; `ResolveDirection`/`HmacKey`/`CipherKey` | [OpenVpnStaticKey.cs:17](OpenVpnStaticKey.cs#L17) |
| `OpenVpnKeyDirection` | enum hướng key tls-auth: `Bidirectional`(0,0)/`Normal`(0,1)/`Inverse`(1,0) | [Enums/OpenVpnKeyDirection.cs:10](Enums/OpenVpnKeyDirection.cs#L10) |
| `OpenVpnKeySource2` | vật liệu random key-method-2 (`PreMaster`/`Random1`/`Random2`); `GenerateClient()` | [DataChannel/OpenVpnKeySource2.cs:14](DataChannel/OpenVpnKeySource2.cs#L14) |
| `OpenVpnKeyMethod2` | static: `BuildClientMessage` / `TryParseServerMessage` / `DeriveDataKeys` (Tls1Prf → master 48 → key2 256, slice qua `OpenVpnStaticKey`) | [DataChannel/OpenVpnKeyMethod2.cs:18](DataChannel/OpenVpnKeyMethod2.cs#L18) |
| `OpenVpnDataChannelKeys` | khóa data plane mỗi chiều: `SendCipherKey`(32)/`SendImplicitIv`(8)/`ReceiveCipherKey`/`ReceiveImplicitIv` | [DataChannel/OpenVpnDataChannelKeys.cs:13](DataChannel/OpenVpnDataChannelKeys.cs#L13) |
| `OpenVpnKeyNegotiation` | client: `NegotiateAsync(options, user?, pass?, peerInfo?)` ghi msg + đọc reply trên `Stream` → `OpenVpnDataChannelKeys` | [DataChannel/OpenVpnKeyNegotiation.cs:11](DataChannel/OpenVpnKeyNegotiation.cs#L11) |
| `OpenVpnDataChannel` | `Protect`/`TryUnprotect` P_DATA_V2 + AES-256-GCM (`AesGcmCipher`), nonce=`packet_id‖implicit_iv`, AAD=header rõ; packet-id `checked(++)` + `AntiReplayWindow` | [DataChannel/OpenVpnDataChannel.cs:24](DataChannel/OpenVpnDataChannel.cs#L24) |
| `OpenVpnProfile` | config lập trình driver tiêu thụ: `Remotes`/`Protocol`/`Port`/`Device`/`IsClient`, TLS material (`Ca`/`Cert`/`Key`/`TlsAuth`/`TlsCrypt`/`KeyDirection`), `Cipher`/`DataCiphers`/`Auth`, `AuthUserPass`, `Compression`/`RenegSec`/`TunMtu`, `OtherDirectives` (raw chưa model) | [Config/OpenVpnProfile.cs:14](Config/OpenVpnProfile.cs#L14) |
| `OpenVpnConfigParser` | static `Parse(text)` → `OpenVpnProfile`: inline `<ca>…</ca>` → PEM, dạng path → `FilePath`; bỏ comment `#`/`;`, hỗ trợ arg trong `"…"`, flatten `<connection>`, directive lạ giữ raw | [Config/OpenVpnConfigParser.cs:16](Config/OpenVpnConfigParser.cs#L16) |
| `OpenVpnRemote` / `OpenVpnFileOrInline` | endpoint `remote host [port] [proto]` / cert-key inline-hoặc-path | [Config/OpenVpnRemote.cs:6](Config/OpenVpnRemote.cs#L6) · [Config/OpenVpnFileOrInline.cs:9](Config/OpenVpnFileOrInline.cs#L9) |

## Wire format (control packet)

```
opcode|key_id (1) | session_id (8) | ack_len (1) | acked_ids (4·M) | [remote_session_id (8) nếu M>0]
                  | [packet_id (4) | payload (…)]   ← chỉ P_CONTROL/reset; P_ACK_V1 bỏ 2 trường cuối
```

- **Byte đầu**: 5-bit opcode (cao) + 3-bit key_id (thấp, tới 8 phiên key chồng cho rekey).
- **session_id**: 64-bit của bên gửi. `remote_session_id` (của peer) chỉ xuất hiện khi có ≥1 ACK.
- **P_ACK_V1**: chỉ mang acks (không packet-id, không payload).
- **TCP** (phase sau): mỗi gói prefix 16-bit length; **UDP**: 1 gói = 1 datagram.

## Reliability layer (V2.a)

OpenVPN chạy TLS **bên trong** một lớp tin cậy tự chế trên control channel (vì UDP không tin cậy, và cả trên TCP để thống nhất). Hai nửa độc lập, **clock được inject** (mọi method liên quan thời gian nhận `nowMs` ms) nên driver bơm từ timer còn test chạy tất định không cần `sleep`:

- **Send** (`OpenVpnReliableSendWindow`): `Queue(payload)` gán packet-id tăng dần (từ 0) vào in-flight window (giới hạn `WindowSize`). `CollectDue(nowMs)` trả gói cần lên dây — gói chưa gửi (gửi ngay) + gói quá `IntervalFor(resends)` (retransmit, backoff tùy chọn) — và đánh dấu đã gửi. `Acknowledge(ids)` xóa gói peer đã ack khỏi window. `IsExhausted(nowMs)` báo peer chết khi một gói dùng hết `1 + MaxRetransmits` lần gửi.
- **Receive** (`OpenVpnReliableReceiveWindow`): `Offer(id,payload)` dedup (gói đã giao / đã buffer / ngoài window) + buffer gói đến lệch thứ tự; `TryDeliver` nhả payload **đúng thứ tự packet-id** cho TLS (gọi lặp tới khi gặp lỗ hổng); `TakeAcks(max)` lấy id cần ack (≤8 đút P_ACK_V1, ≤4 piggyback lên P_CONTROL). Mọi id nhận được (kể cả trùng) đều xếp lại để ack vì peer resend tới khi thấy ack.

## Control channel — TLS-in-control (V2.b)

`OpenVpnControlChannel` (client) là object ráp 2 window + codec + session-id (64-bit random) + transport `IOpenVpnTransport`, rồi chạy TLS **bên trong** lớp tin cậy:

- **`ConnectAsync(targetHost, clientCertificates?, serverCertificateValidation?, ct)`**: (1) gửi **P_CONTROL_HARD_RESET_CLIENT_V2** (reliability packet-id 0), chờ **P_CONTROL_HARD_RESET_SERVER_V2** (học `RemoteSessionId` của peer); (2) dựng `SslStream` trên `OpenVpnTlsBridgeStream` rồi `AuthenticateAsClient` — bản ghi TLS đi trên packet-id 1+. Xong thì `TlsStream` là pipe đã xác thực cho key-method-2 + data channel (V2.d). Quy ước opcode: packet-id 0 ⇒ reset, còn lại ⇒ `P_CONTROL_V1`.
- **`OpenVpnTlsBridgeStream`** (internal): `Stream` nối SslStream vào reliability layer. Write từ TLS → cắt mảnh ≤1200 B, mỗi mảnh `Queue` vào send window (chờ chỗ trống window = backpressure) rồi pump. Read ← payload **in-order** mà control channel `EnqueueInbound` từ receive window. Một reader duy nhất (SslStream) nên đường vào nối tiếp.
- **Pump (timer)**: gom gói `CollectDue` (gửi mới + retransmit) đính kèm ack piggyback (≤4), phần ack còn lại (hoặc khi rảnh) gửi **P_ACK_V1** riêng (≤8). Ack đến từ peer xóa gói khỏi send window + nhả slot backpressure. `RemoteSessionId` chỉ kèm khi gói mang ≥1 ack.
- **Thuần client**: vai trò responder (đáp reset + TLS server) chỉ nằm trong test harness.

## Control packet wrap — tls-auth / tls-crypt (V2.c)

`OpenVpnControlChannel` nhận một `IOpenVpnControlWrap?` ở ctor (null = gửi gói verbatim, mặc định OpenVPN không có chỉ thị nào). Wrap là **codec byte→byte** quanh `EncodeControl`/`TryDecodeControl`: Pump bọc trước khi `SendAsync`, `OnDatagram` giải-bọc trước khi decode (giải-bọc thất bại ⇒ **drop datagram**, vì xác thực sai/không-phải-của-ta). Áp cho **mọi** gói control kể cả `HARD_RESET` đầu tiên. Cả hai là crypto đối xứng — client cần cả wrap (gói gửi) lẫn unwrap (gói server) — không thêm code server.

- **`OpenVpnStaticKey`** — parse `ta.key` 2048-bit (block `-----BEGIN OpenVPN Static key V1-----`, 16 dòng × 32 hex = 256 B). 256 B là cấu trúc `key2`: 2 bộ `cipher[64] | hmac[64]`. `ResolveDirection(dir)` → cặp (set out, set in); `HmacKey`/`CipherKey(set, len)` cắt khóa.
- **`OpenVpnTlsAuthWrap`** (`--tls-auth`) — HMAC xác thực (gói vẫn rõ), thêm replay-id + timestamp gộp vào HMAC. Wire `op(1)|sid(8)|HMAC(N)|replay_id(4)|net_time(4)|body`; `HMAC = H(K_out, replay_id|net_time|op|sid|body)`. Digest mặc định **SHA1** (theo `--auth`), dùng được SHA256… (key = N byte đầu của hmac-half). Hướng key theo `OpenVpnKeyDirection`: client thường `Inverse` (`key-direction 1`) hoặc `Bidirectional` (khi profile bỏ trống).
- **`OpenVpnTlsCryptWrap`** (`--tls-crypt`) — xác thực **+ mã hóa**, thuật toán **cố định** HMAC-SHA256 (tag 32 B) + AES-256-CTR (tái dùng [`Crypto.AesCtr`](../TqkLibrary.VpnClient.Crypto/AesCtr.cs)). Wire `op(1)|sid(8)|packet_id(4)|net_time(4)|tag(32)|E(body)`; `tag = HMAC256(Ka, op|sid|packet_id|net_time|body)`, **IV = tag[0..16]**, chỉ `body` (acks + control-id + mảnh TLS) được mã, header + packet-id rõ để xác thực. Không có `key-direction` — hướng **cố định theo role** (client mã bằng set 1, giải bằng set 0; server ngược lại).

## Key-method-2 + data channel AEAD (V2.d)

Sau khi `SslStream` xác thực xong (V2.b), client suy ra khóa data plane qua **key-method-2** rồi gói gói tin bằng **P_DATA_V2 + AES-256-GCM**:

- **Trao đổi** ([`OpenVpnKeyNegotiation`](DataChannel/OpenVpnKeyNegotiation.cs), hook [`OpenVpnControlChannel.NegotiateDataChannelKeysAsync`](OpenVpnControlChannel.cs)): client ghi lên `TlsStream` message `uint32 0 | key_method=2 | key_source2 | P_string(options) | P_string(user) | P_string(pass)` — `key_source2` của client = pre-master 48 + random1 32 + random2 32; rồi đọc reply server (chỉ 2 random + options). `P_string` = u16 độ dài (kể NUL) + bytes + NUL.
- **Suy khóa** ([`OpenVpnKeyMethod2.DeriveDataKeys`](DataChannel/OpenVpnKeyMethod2.cs)): `master = Tls1Prf(pre_master, "OpenVPN master secret", c.random1‖s.random1)` (48B); `key2 = Tls1Prf(master, "OpenVPN key expansion", c.random2‖s.random2‖client_sid‖server_sid)` (256B). `key2` cùng layout static-key nên **tái dùng `OpenVpnStaticKey`** để cắt; hướng client out=set1/in=set0. Mỗi chiều lấy cipher key 32B (AES-256) + **implicit IV 8B** (từ nửa hmac) → [`OpenVpnDataChannelKeys`](DataChannel/OpenVpnDataChannelKeys.cs). `Tls1Prf` (PRF TLS 1.0 MD5⊕SHA1) nằm ở [Crypto](../TqkLibrary.VpnClient.Crypto).
- **Data plane** ([`OpenVpnDataChannel`](DataChannel/OpenVpnDataChannel.cs)): wire `op|key_id(1) | peer_id(3) | packet_id(4) | tag(16) | ciphertext`; **nonce(12) = packet_id ‖ implicit_iv(8)**; **AAD = header rõ** (op+peer_id+packet_id); tag đứng **trước** ciphertext. `Protect` tăng packet-id `checked(++)` từ 1 (tràn 2³² ⇒ `OverflowException`, phải rekey V2.e trước khi lặp nonce); `TryUnprotect` chạy [`AntiReplayWindow`](../TqkLibrary.VpnClient.Crypto/AntiReplayWindow.cs) 64-gói (dùng chung ESP) + xác thực GCM (`AesGcmCipher`). peer-id mặc định 0 (server cấp qua PUSH_REPLY ở V2.e).
- **Thuần client**: vai trò server (parse client msg / build reply / suy khóa role server) chỉ trong test; **direction key data-plane + interop chờ validate lab Q.1**; `tls-ekm` (RFC 5705) chờ **F.5** (`SslStream` net8 chưa lộ keying-material exporter).

## Config (`.ovpn` + model lập trình)

Hai lớp tách bạch để vừa dùng được file `.ovpn` vừa cấu hình tay, mà **lõi driver chỉ phụ thuộc model** (test offline sạch):

- **`OpenVpnProfile`** — thứ driver (V2.b+) tiêu thụ: remote(s)/proto/port/device, TLS material (CA/cert/key/tls-auth/tls-crypt + key-direction), cipher/data-ciphers/auth, auth-user-pass, comp/reneg/mtu. Directive parser chưa model giữ nguyên trong `OtherDirectives` (không mất gì).
- **`OpenVpnConfigParser.Parse(text)`** — **thuần text→model, không I/O**: cert/key **inline** (`<ca>…</ca>`) giữ nguyên PEM; dạng **đường dẫn** (`ca ca.crt`) chỉ ghi `FilePath` cho caller tự nạp (I/O thuộc tầng driver/app). Bỏ comment `#`/`;`, hỗ trợ arg trong `"…"`, flatten `<connection>`, inline thắng path khi trùng. Nhiều `remote` → danh sách (mỗi cái port/proto riêng, fallback default).

## Bảng chuẩn / nguồn

| Chuẩn / nguồn | Dùng ở | Ghi chú |
|---------------|--------|---------|
| OpenVPN wire protocol (WIP RFC) | codec | https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html |
| OpenVPN network protocol (doxygen) | reliability (phase sau) | https://build.openvpn.net/doxygen/network_protocol.html |
| tls-crypt wire format (spec) | `OpenVpnTlsCryptWrap` | HMAC-SHA256 + AES-256-CTR, IV = tag[0..16]; doc/tls-crypt-v2.txt (v1 format) |
| tls-auth (HMAC firewall) | `OpenVpnTlsAuthWrap` | HMAC bọc control packet + replay-id/timestamp; `key2` direction theo `--key-direction` |
| key-method-2 + TLS 1.0 PRF | `OpenVpnKeyMethod2`/`Tls1Prf` | RFC 2246 §5 PRF (P_MD5⊕P_SHA1); master "OpenVPN master secret" + "OpenVPN key expansion" |
| AEAD data channel (P_DATA_V2) | `OpenVpnDataChannel` | AES-256-GCM, nonce=packet_id‖implicit_iv, tag trước ciphertext, AAD=header rõ |

## Trạng thái & ghi chú

- **Thuần client**, thuần protocol: không I/O, không server. Đọc spec/behavior từ nguồn OpenVPN (**không copy GPL source**).
- Build xanh cả `netstandard2.0` + `net8.0`. Codec dùng `System.Buffers.Binary.BinaryPrimitives` (có ở cả 2 TFM qua `System.Memory`), Span trong method non-async (an toàn C# 12). Wrap V2.c dùng `IncrementalHash.CreateHMAC` (HMAC nhiều đoạn, có ở cả 2 TFM) + `Crypto.AesCtr`; so tag bằng `FixedTimeEquals` tự viết (constant-time, không phụ thuộc `CryptographicOperations` của net5+). Data channel V2.d tái dùng `Crypto.Tls1Prf` (PRF) + `Crypto.AesGcmCipher` (AEAD) + `Crypto.AntiReplayWindow`; `Protect`/`TryUnprotect` non-async nên `stackalloc` nonce an toàn C# 12. `OpenVpnControlChannel` xử lý `SslStream` theo TFM giống [`TlsByteStream`](../TqkLibrary.VpnClient.Drivers.Sstp/Transport/TlsByteStream.cs): net5+ dùng `SslClientAuthenticationOptions` + `ct`; netstandard2.0 dùng overload cũ + cancel-bằng-dispose.
- Lộ trình V.2 đầy đủ ở [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.2; thiết kế ở [`.docs/06-openvpn.md`](../../.docs/06-openvpn.md).
