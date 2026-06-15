# TqkLibrary.VpnClient.OpenVpn

Thư viện **protocol OpenVPN** thuần .NET (tương thích OpenVPN community server) — **không dùng PPP**. Control channel (TLS) + data channel ghép trên một socket UDP/TCP, demux theo byte opcode đầu. Đây là project protocol-level cho driver **V.2** (đang xây theo phase, xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.2).

> **Trạng thái:** **V2.a reliability-layer + config/.ovpn + V2.b TLS-in-control + V2.c tls-auth/tls-crypt + V2.d data channel AEAD xong**. Đã có: (1) codec gói control (opcode/key-id + session-id + ACK array + packet-id + payload); (2) reliability state machine — send window (gán packet-id + retransmit/backoff theo clock inject) + receive window (dedup + in-order delivery cho TLS + theo dõi ACK); (3) **`OpenVpnProfile` (config lập trình driver tiêu thụ) + `OpenVpnConfigParser` đọc `.ovpn`** (cert/key inline → PEM, dạng path → giữ đường dẫn cho caller; không I/O); (4) **`OpenVpnControlChannel` (client)** — ráp 2 window + codec + session-id + transport `IOpenVpnTransport`, làm reset HARD_RESET_CLIENT_V2 ⇄ HARD_RESET_SERVER_V2 rồi chạy `SslStream` thật trên `OpenVpnTlsBridgeStream` in-memory (TLS **bên trong** reliability layer); (5) **`IOpenVpnControlWrap`** — bọc/giải-bọc control packet: `OpenVpnTlsAuthWrap` (`--tls-auth` HMAC) + `OpenVpnTlsCryptWrap` (`--tls-crypt` HMAC + AES-256-CTR) trên `OpenVpnStaticKey` (`ta.key` 2048-bit), opt-in ở ctor channel; (6) **key-method-2 + data channel AEAD** — `OpenVpnKeyNegotiation` trao đổi key_source2 trên `TlsStream`, `OpenVpnKeyMethod2`/`Tls1Prf` suy khóa, `OpenVpnDataChannel` gói **P_DATA_V2 + AES-256-GCM** (`AesGcmCipher`) + anti-replay 64-gói; (7) **config-pull + keepalive + make-before-break** — `RequestConfigAsync` (PUSH_REQUEST/PUSH_REPLY) → `OpenVpnPushReply` → `TunnelConfig`, `OpenVpnPing`/`OpenVpnKeepalive` (ping magic + timing), `OpenVpnDataPlane` giữ current+previous channel (mirror `EspDataPlane`); (8) **NCP + compression stub** — `OpenVpnDataCipher` (AES-256/128-GCM **+ CHACHA20-POLY1305** catalog), `OpenVpnPeerInfo`/`OpenVpnPeerInfoOptions` (IV_CIPHERS + push-peer-info nâng cao: IV_MTU/IV_PLAT/IV_PLAT_VER/IV_SSL_VER/IV_GUI_VER + `UV_*`), suy khóa tách `DeriveKey2`/`SliceDataKeys` chốt cipher sau PUSH_REPLY (`OpenVpnKeyMaterial`), `OpenVpnCompression` (chỉ chào no-compression); (9) **transport TCP + tap-mode (V2.g)** — `OpenVpnTcpFraming` (16-bit length framing, seam F.2) + `OpenVpnTcpTransport` (bọc `IByteStreamTransport` F.1 thành `IOpenVpnTransport`), cầu nối `OpenVpnDataLink` → `OpenVpnTunChannel` (`dev tun`→`IPacketChannel`) / `OpenVpnTapChannel` (`dev tap`→`IEthernetChannel` cắm fabric Ethernet). **driver [`Drivers.OpenVpn`](../TqkLibrary.VpnClient.Drivers.OpenVpn) (V2.h)** ráp các khối trên thành tunnel **tun/tap** chạy thật (demux opcode + chọn transport UDP/TCP + handshake + NCP + keepalive/reconnect + `UseOpenVpn()`; tap bắc cầu `OpenVpnTapChannel`→`ArpResolver`+`VirtualHost`→`IPacketChannel`, 1 host IPv4 từ server-bridge ifconfig). Cả 3 AEAD (AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305) chạy thật ở data channel — server pick cipher nào trong PUSH `cipher` cũng chốt được. **Chưa**: `tls-ekm` (chờ F.5), soft-reset make-before-break, tap pure-DHCP-bridge/IPv6/multi-host (chờ L2.5/L2.4/L2.7+); **direction key + interop chờ lab Q.1**.

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [Ipsec](../TqkLibrary.VpnClient.Ipsec)/[L2tp](../TqkLibrary.VpnClient.L2tp)/[Ppp](../TqkLibrary.VpnClient.Ppp)): các khối giao thức thuần, **không** I/O socket — driver `Drivers.OpenVpn` (V.2, chưa có) sẽ lắp ráp thành tunnel sống. Reliability layer của OpenVPN tương tự vai trò control-channel của [L2tp](../TqkLibrary.VpnClient.L2tp) (Ns/Nr + retransmit) nhưng dùng **packet-id 32-bit + ACK array** thay cho sequence 16-bit.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `TunnelConfig` (đích của PUSH_REPLY, V2.e); `IByteStreamTransport` (TCP transport V2.g, F.1) + `IDatagramTransport` (UDP transport V2.h), `IPacketChannel`/`IEthernetChannel` (tun/tap link V2.g); các phase sau: exceptions, `IHostResolver` |
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
│  ├─ OpenVpnKeyNegotiation.cs     Chạy trao đổi key-method-2 trên TlsStream → OpenVpnKeyMaterial
│  ├─ OpenVpnKeyMaterial.cs        key2 256B (cipher-independent) → DeriveDataKeys(cipher) sau PUSH_REPLY (NCP)
│  ├─ OpenVpnDataCipher.cs         Catalog cipher NCP (AES-256/128-GCM + CHACHA20-POLY1305): name/keySize/factory + resolve + IV_CIPHERS
│  ├─ OpenVpnPeerInfo.cs           Build IV_* peer-info (IV_PROTO/IV_NCP/IV_CIPHERS + IV_MTU/IV_PLAT auto + UV_*) cho key-method-2; cấu hình qua OpenVpnPeerInfoOptions
│  ├─ OpenVpnCompression.cs        Framing stub (None/comp-lzo/stub-v2) — chỉ chào no-compression
│  ├─ OpenVpnDataChannel.cs        Protect/TryUnprotect P_DATA_V2 + AES-GCM (tự-chọn theo key) + anti-replay
│  ├─ OpenVpnControlMessage.cs     Control string NUL-terminated trên TLS (PUSH_REQUEST/PUSH_REPLY…) — V2.e
│  ├─ OpenVpnPushReply.cs          Parse PUSH_REPLY (ifconfig/route/DNS/peer-id/ping/cipher) → TunnelConfig
│  ├─ OpenVpnPing.cs               Ping magic 16B (keepalive qua data channel)
│  ├─ OpenVpnKeepalive.cs          Timing ping/ping-restart clock-inject (ShouldSendPing/IsPeerDead)
│  └─ OpenVpnDataPlane.cs          Make-before-break: current+previous data channel + RekeyNeeded (mirror EspDataPlane)
├─ Config/
│  ├─ OpenVpnProfile.cs            Config lập trình (remote, proto, device, TLS material, cipher/auth, options)
│  ├─ OpenVpnConfigParser.cs       Parse text .ovpn → OpenVpnProfile (pure, không I/O)
│  ├─ OpenVpnRemote.cs             1 endpoint `remote host [port] [proto]`
│  └─ OpenVpnFileOrInline.cs       cert/key: inline PEM hoặc đường dẫn file
├─ Transport/
│  ├─ OpenVpnTcpFraming.cs         TCP 16-bit length framing (encode + reassemble) — seam F.2 — V2.g
│  ├─ OpenVpnTcpTransport.cs       Bọc IByteStreamTransport (F.1) thành IOpenVpnTransport — V2.g
│  ├─ OpenVpnUdpTransport.cs       Bọc IDatagramTransport (UDP) thành IOpenVpnTransport (không framing) — V2.h
│  ├─ OpenVpnDataLink.cs           Base cầu nối data plane + compression ↔ sink transport — V2.g
│  ├─ OpenVpnTunChannel.cs         dev tun → IPacketChannel (L3, payload = gói IP) — V2.g
│  └─ OpenVpnTapChannel.cs         dev tap → IEthernetChannel (L2, payload = khung Ethernet) — V2.g
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
| `OpenVpnControlChannel` | control channel client: ctor nhận `controlWrap?` (tls-auth/tls-crypt); `ConnectAsync(...)` reset + `SslStream` AuthenticateAsClient; `NegotiateKeyMaterialAsync(...)` key-method-2 → `OpenVpnKeyMaterial` (V2.d); `RequestConfigAsync(...)` PUSH_REQUEST→PUSH_REPLY (V2.e); `LocalSessionId`/`RemoteSessionId`/`KeyId`/`TlsStream` | [OpenVpnControlChannel.cs:21](OpenVpnControlChannel.cs#L21) |
| `OpenVpnTlsBridgeStream` *(internal)* | `Stream` in-memory cho SslStream: `WriteAsync`→fragment+gửi reliable (callback), `ReadAsync`←payload in-order qua `EnqueueInbound`; `CompleteInbound` đóng | [OpenVpnTlsBridgeStream.cs:15](OpenVpnTlsBridgeStream.cs#L15) |
| `IOpenVpnControlWrap` | seam bọc control packet trên dây: `Wrap(controlPacket)` / `TryUnwrap(wire, out controlPacket)` (byte→byte quanh codec; unwrap-fail ⇒ drop) | [IOpenVpnControlWrap.cs:12](IOpenVpnControlWrap.cs#L12) |
| `OpenVpnTlsAuthWrap` | `--tls-auth`: HMAC (mặc định SHA1) bọc — `op\|sid\|HMAC\|replay_id\|net_time\|body`, key out/in theo `OpenVpnKeyDirection`; `FixedTimeEquals` so tag | [OpenVpnTlsAuthWrap.cs:19](OpenVpnTlsAuthWrap.cs#L19) |
| `OpenVpnTlsCryptWrap` | `--tls-crypt`: HMAC-SHA256 + AES-256-CTR (`Crypto.AesCtr`, IV=tag[0..16]) — `op\|sid\|packet_id(8)\|tag(32)\|E(body)`, hướng cố định theo role | [OpenVpnTlsCryptWrap.cs:21](OpenVpnTlsCryptWrap.cs#L21) |
| `OpenVpnStaticKey` | parse `ta.key` 2048-bit (`Parse`/`FromBytes`); `key2` = 2 bộ `cipher[64]\|hmac[64]`; `ResolveDirection`/`HmacKey`/`CipherKey` | [OpenVpnStaticKey.cs:17](OpenVpnStaticKey.cs#L17) |
| `OpenVpnKeyDirection` | enum hướng key tls-auth: `Bidirectional`(0,0)/`Normal`(0,1)/`Inverse`(1,0) | [Enums/OpenVpnKeyDirection.cs:10](Enums/OpenVpnKeyDirection.cs#L10) |
| `OpenVpnKeySource2` | vật liệu random key-method-2 (`PreMaster`/`Random1`/`Random2`); `GenerateClient()` | [DataChannel/OpenVpnKeySource2.cs:14](DataChannel/OpenVpnKeySource2.cs#L14) |
| `OpenVpnKeyMethod2` | static: `BuildClientMessage` / `TryParseServerMessage` / `DeriveDataKeys` (Tls1Prf → master 48 → key2 256, slice qua `OpenVpnStaticKey`) | [DataChannel/OpenVpnKeyMethod2.cs:18](DataChannel/OpenVpnKeyMethod2.cs#L18) |
| `OpenVpnDataChannelKeys` | khóa data plane mỗi chiều: `SendCipherKey`(32)/`SendImplicitIv`(8)/`ReceiveCipherKey`/`ReceiveImplicitIv` | [DataChannel/OpenVpnDataChannelKeys.cs:13](DataChannel/OpenVpnDataChannelKeys.cs#L13) |
| `OpenVpnKeyNegotiation` | client: `NegotiateAsync(options, user?, pass?, peerInfo?)` ghi msg + đọc reply trên `Stream` → `OpenVpnKeyMaterial` | [DataChannel/OpenVpnKeyNegotiation.cs:11](DataChannel/OpenVpnKeyNegotiation.cs#L11) |
| `OpenVpnKeyMaterial` | key2 256B cipher-independent; `DeriveDataKeys(cipher, isServer?)` slice sau khi biết cipher (NCP) | [DataChannel/OpenVpnKeyMaterial.cs:9](DataChannel/OpenVpnKeyMaterial.cs#L9) |
| `OpenVpnDataCipher` | catalog cipher NCP: `Aes256Gcm`/`Aes128Gcm`/`ChaCha20Poly1305`, `TryResolve(name)`, `AdvertisedList`, `KeySizeBytes`, `CreateCipher()` | [DataChannel/OpenVpnDataCipher.cs:12](DataChannel/OpenVpnDataCipher.cs#L12) |
| `OpenVpnPeerInfo` | static `Build(OpenVpnPeerInfoOptions?)` → khối `IV_*` (IV_VER/IV_PLAT/IV_PROTO/IV_NCP=2/IV_CIPHERS + IV_MTU + IV_PLAT_VER/IV_SSL_VER/IV_GUI_VER + `UV_*`) cho key-method-2; `DetectPlatform`/`DetectPlatformVersion`/`DetectSslVersion` + hằng IV_PROTO bit (DataV2/RequestPush/TlsKeyExport/CcExitNotify) | [DataChannel/OpenVpnPeerInfo.cs:16](DataChannel/OpenVpnPeerInfo.cs#L16) |
| `OpenVpnPeerInfoOptions` | record cấu hình peer-info: `Ciphers`/`IvProto`/`Version`/`Platform`/`Mtu`/`PlatformVersion`/`SslVersion`/`GuiVersion`/`Extra` (UV_* và IV_* tuỳ biến) — **push-peer-info nâng cao** | [DataChannel/OpenVpnPeerInfo.cs:85](DataChannel/OpenVpnPeerInfo.cs#L85) |
| `OpenVpnCompression` | framing stub `WrapOutgoing`/`TryUnwrapIncoming` (None/CompLzo/StubV2); `FromPushReply`; gói nén thật ⇒ reject | [DataChannel/OpenVpnCompression.cs:11](DataChannel/OpenVpnCompression.cs#L11) |
| `OpenVpnDataChannel` | `Protect`/`TryUnprotect` P_DATA_V2 + AES-256-GCM (`AesGcmCipher`), nonce=`packet_id‖implicit_iv`, AAD=header rõ; packet-id `checked(++)` + `AntiReplayWindow` | [DataChannel/OpenVpnDataChannel.cs:24](DataChannel/OpenVpnDataChannel.cs#L24) |
| `OpenVpnControlMessage` | static: `Build(text)` (ascii+NUL) / `ReadAsync(stream)` đọc tới NUL — control string trên TLS | [DataChannel/OpenVpnControlMessage.cs:12](DataChannel/OpenVpnControlMessage.cs#L12) |
| `OpenVpnPushReply` | `TryParse(msg)` → `IfconfigLocal`/`Routes`/`DnsServers`/`PeerId`/`Ping`/`PingRestart`/`Cipher`/`Topology`; `ToTunnelConfig()` | [DataChannel/OpenVpnPushReply.cs:14](DataChannel/OpenVpnPushReply.cs#L14) |
| `OpenVpnPing` | static: `Magic` 16B + `IsPing(plaintext)` — keepalive gói qua data channel | [DataChannel/OpenVpnPing.cs:8](DataChannel/OpenVpnPing.cs#L8) |
| `OpenVpnKeepalive` | timing clock-inject: `OnDataSent`/`OnDataReceived`/`ShouldSendPing(nowMs)`/`IsPeerDead(nowMs)` (ping/ping-restart; 0 = tắt) | [DataChannel/OpenVpnKeepalive.cs:13](DataChannel/OpenVpnKeepalive.cs#L13) |
| `OpenVpnDataPlane` | make-before-break (mirror `EspDataPlane`): `Protect`/`TryUnprotect` current+previous, `Swap(next)`/`DropPreviousInbound`, event `RekeyNeeded` quanh 2³² | [DataChannel/OpenVpnDataPlane.cs:11](DataChannel/OpenVpnDataPlane.cs#L11) |
| `OpenVpnTcpFraming` | TCP framing (V2.g, seam F.2): `Encode(packet)` prepend 16-bit BE length; decoder `Append(chunk)` + `TryReadPacket(out)` ráp gói qua mọi ranh đọc | [Transport/OpenVpnTcpFraming.cs:18](Transport/OpenVpnTcpFraming.cs#L18) |
| `OpenVpnTcpTransport` | adapter `IByteStreamTransport`(F.1)→`IOpenVpnTransport`: `SendAsync` length-prefix + write nối tiếp; `RunReceiveLoopAsync` đọc→ráp→`DatagramReceived` | [Transport/OpenVpnTcpTransport.cs:14](Transport/OpenVpnTcpTransport.cs#L14) |
| `OpenVpnUdpTransport` | adapter `IDatagramTransport`(UDP)→`IOpenVpnTransport` (V2.h): 1 datagram = 1 gói nên **không framing**; `SendAsync` gửi 1 datagram; `RunReceiveLoopAsync` raise `DatagramReceived` mỗi datagram, 0-byte không phải EOF | [Transport/OpenVpnUdpTransport.cs:15](Transport/OpenVpnUdpTransport.cs#L15) |
| `OpenVpnDataLink` *(abstract)* | base cầu nối: `SendPayloadAsync` (compression-frame + `OpenVpnDataPlane.Protect` → sink) / `TryReceivePayload` (TryUnprotect + de-frame) / `Deliver(wire)` | [Transport/OpenVpnDataLink.cs:15](Transport/OpenVpnDataLink.cs#L15) |
| `OpenVpnTunChannel` | `dev tun` → `IPacketChannel` (Medium=Ip, MaxHeaderLength 0): `WriteIpPacketAsync`/`InboundIpPacket` qua data channel | [Transport/OpenVpnTunChannel.cs:12](Transport/OpenVpnTunChannel.cs#L12) |
| `OpenVpnTapChannel` | `dev tap` → `IEthernetChannel` (Medium=Ethernet, MaxHeaderLength 14, MAC + resolution): `WriteFrameAsync`/`InboundFrame` qua data channel | [Transport/OpenVpnTapChannel.cs:15](Transport/OpenVpnTapChannel.cs#L15) |
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
- **TCP** (V2.g, `OpenVpnTcpFraming`): mỗi gói prefix 16-bit big-endian length; **UDP**: 1 gói = 1 datagram.

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

## Config-pull + keepalive + soft-reset (V2.e)

Sau khi data channel có khóa (V2.d), client kéo cấu hình + duy trì kết nối:

- **Config pull** ([`OpenVpnControlMessage`](DataChannel/OpenVpnControlMessage.cs) + [`OpenVpnControlChannel.RequestConfigAsync`](OpenVpnControlChannel.cs)): control message **text NUL-terminated** trên `TlsStream` (khác key-method-2: **không** có 4-byte sentinel — chỉ chạy sau khi đàm phán khóa nên reader tuần tự). Client gửi `PUSH_REQUEST`, đọc `PUSH_REPLY,…`; [`OpenVpnPushReply.TryParse`](DataChannel/OpenVpnPushReply.cs) tách `ifconfig`/`route`/`dhcp-option DNS`/`peer-id`/`ping`/`ping-restart`/`cipher`/`topology` (option lạ giữ verbatim ở `Options`); `ToTunnelConfig()` map sang [`TunnelConfig`](../TqkLibrary.VpnClient.Abstractions/Drivers/Models/TunnelConfig.cs) — `subnet` lấy prefix từ netmask, `net30`/p2p → /30. `AUTH_FAILED` ⇒ ném.
- **Keepalive** ([`OpenVpnPing`](DataChannel/OpenVpnPing.cs) + [`OpenVpnKeepalive`](DataChannel/OpenVpnKeepalive.cs)): ping là gói **data channel** mang magic 16B cố định (mã hóa như payload thường); bên nhận giải mã thấy magic ⇒ không forward lên IP stack. `OpenVpnKeepalive` (clock-inject như reliability) báo `ShouldSendPing` khi im lặng gửi ≥ `ping` giây, `IsPeerDead` khi im lặng nhận ≥ `ping-restart` giây (0 = tắt) — driver bơm từ timer.
- **Soft-reset make-before-break** ([`OpenVpnDataPlane`](DataChannel/OpenVpnDataPlane.cs), **mirror `EspDataPlane`**): giữ data channel **current + previous**; gửi trên current, nhận thử current rồi previous (sai khóa fail GCM tag) ⇒ rekey không mất gói in-flight. `Swap(next)` cài thế hệ mới, `DropPreviousInbound` bỏ thế hệ cũ sau grace; `RekeyNeeded` phát quanh 2³² packet-id (nonce GCM không được lặp). **Điều phối control-plane** (P_CONTROL_SOFT_RESET_V1 → chạy TLS handshake thứ 2 trên key_id mới → `Swap`) thuộc **driver `Drivers.OpenVpn`** (chưa có) — giống rekey IKE/ESP nằm ở connection chứ không ở protocol layer.

## NCP cipher negotiation + compression stub (V2.f)

- **NCP** ([`OpenVpnDataCipher`](DataChannel/OpenVpnDataCipher.cs) + [`OpenVpnPeerInfo`](DataChannel/OpenVpnPeerInfo.cs)): client chào danh sách cipher qua peer-info `IV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305` (+ `IV_PROTO`/`IV_NCP=2`) trong key-method-2; server chọn 1 và trả ở `PUSH_REPLY` (`cipher …`); `OpenVpnDataCipher.TryResolve(name)` map lại (key size + factory AEAD). Vì cipher chỉ biết **sau PUSH_REPLY**, suy khóa tách 2 bước: [`OpenVpnKeyMethod2.DeriveKey2`](DataChannel/OpenVpnKeyMethod2.cs) (key2 256B, **cipher-independent**, do `NegotiateAsync` trả qua [`OpenVpnKeyMaterial`](DataChannel/OpenVpnKeyMaterial.cs)) rồi [`SliceDataKeys(key2, cipher, isServer)`](DataChannel/OpenVpnKeyMethod2.cs) cắt theo `KeySizeBytes` (16 cho AES-128, 32 cho AES-256/ChaCha20). Driver truyền `cipher.CreateCipher()` vào `OpenVpnDataChannel` — `AesGcmCipher` (theo độ dài khóa) hoặc `ChaCha20Poly1305Cipher`; cả 3 cùng shape AEAD nonce 12B/tag 16B nên data plane không đổi. **Push-peer-info nâng cao**: ngoài `IV_CIPHERS`/`IV_PROTO`/`IV_NCP`, [`OpenVpnPeerInfoOptions`](DataChannel/OpenVpnPeerInfo.cs#L85) còn cho client advertise `IV_MTU` (driver bơm tun MTU để server đẩy MTU đúng), `IV_PLAT` auto-detect (linux/win/mac), thông tin `IV_PLAT_VER`/`IV_SSL_VER`/`IV_GUI_VER`, và user-var `UV_*` (qua `Extra`) — đúng khối mà OpenVPN 2.6 gửi dưới `--push-peer-info`.
- **Compression stub** ([`OpenVpnCompression`](DataChannel/OpenVpnCompression.cs)): client chỉ **chào no-compression**; codec thêm/bóc framing nhưng **không bao giờ nén**. `None` passthrough; `CompLzo` (`comp-lzo`/`comp-lzo no`) thêm 1 byte `0xFA`; `StubV2` (`compress stub-v2`) zero-overhead cho gói IP (chỉ escape khi byte đầu trùng `0x50`). Gói **thật-sự-nén** đến ⇒ `TryUnwrapIncoming` trả false (đã chào stub). `FromPushReply` map directive → mode. Đặt giữa IP packet và data channel (driver áp).

## Transport TCP + tap-mode (V2.g)

- **TCP framing** ([`OpenVpnTcpFraming`](Transport/OpenVpnTcpFraming.cs)): trên stream transport, mỗi gói OpenVPN được prefix **16-bit big-endian length** để ranh giới "1 gói" của `IOpenVpnTransport` sống sót qua byte-stream của TCP — đây là hiện thực OpenVPN của seam **F.2 `IPacketEncapsulator`** (đối xứng SSTP 4-byte framing). `Encode` egress; decoder instance (`Append` + `TryReadPacket`) ráp lại gói nguyên qua **mọi ranh đọc** (gói cắt nhiều read, hoặc nhiều gói gộp một read). UDP không cần (1 datagram = 1 gói).
- **TCP transport** ([`OpenVpnTcpTransport`](Transport/OpenVpnTcpTransport.cs)): bọc một byte-stream tin cậy ([`IByteStreamTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IByteStreamTransport.cs) — TCP, hoặc TCP+TLS qua **F.1**) thành `IOpenVpnTransport`: `SendAsync` length-prefix + write (nối tiếp qua semaphore để 2 send không xen khung); `RunReceiveLoopAsync` đọc stream, ráp gói nguyên, raise `DatagramReceived`.
- **UDP transport** ([`OpenVpnUdpTransport`](Transport/OpenVpnUdpTransport.cs), V2.h): bọc một datagram-pipe ([`IDatagramTransport`](../TqkLibrary.VpnClient.Abstractions/Transport/Interfaces/IDatagramTransport.cs) — UDP) thành `IOpenVpnTransport`. Trên UDP **1 datagram đã là 1 gói** nên — khác TCP — **không có length framing**: `SendAsync` gửi gói thành 1 datagram, `RunReceiveLoopAsync` raise `DatagramReceived` mỗi datagram đọc được. Datagram 0-byte **không** phải end-of-stream (UDP không có close) nên vòng lặp bỏ qua và lắng nghe tiếp; chỉ kết thúc khi cancel.
- **tun/tap link** ([`OpenVpnDataLink`](Transport/OpenVpnDataLink.cs) + 2 hiện thực): data channel **payload-agnostic** — chỉ khác nội dung payload + medium kênh. [`OpenVpnTunChannel`](Transport/OpenVpnTunChannel.cs) (`dev tun`) lộ data channel thành **L3 `IPacketChannel`** (payload = gói IP, MaxHeaderLength 0, không resolution) để IP stack bind thẳng; [`OpenVpnTapChannel`](Transport/OpenVpnTapChannel.cs) (`dev tap`) lộ thành **L2 `IEthernetChannel`** (payload = khung Ethernet, MaxHeaderLength 14, MAC + resolution) để **cắm fabric Ethernet** (ARP/DHCP/switch → IP stack). Base ráp compression-framing + `OpenVpnDataPlane.Protect`/`TryUnprotect` quanh một sink transport (UDP send / `OpenVpnTcpTransport`); driver route gói **P_DATA sau demux opcode** vào `Deliver`. `TryReceivePayload` **drop gói keepalive ping** (`OpenVpnPing.IsPing`) sau giải mã+de-compress nên ping không lọt lên IP/Ethernet layer. Bind tun→stack / tap→fabric + demux + chọn transport là việc của **driver [`Drivers.OpenVpn`](../TqkLibrary.VpnClient.Drivers.OpenVpn)** (V2.h — **tun và tap đã chạy**: tap bắc cầu `OpenVpnTapChannel`→`VirtualHost`+`ArpResolver`→`IPacketChannel` 1 host IPv4 từ server-bridge ifconfig; pure-DHCP-bridge/IPv6/multi-host chờ L2.5/L2.4/L2.7+).

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
| AEAD data channel (P_DATA_V2) | `OpenVpnDataChannel` | AEAD đàm phán (AES-256/128-GCM, ChaCha20-Poly1305 RFC 8439), nonce=packet_id‖implicit_iv, tag trước ciphertext, AAD=header rõ |
| PUSH config + keepalive | `OpenVpnPushReply`/`OpenVpnKeepalive` | PUSH_REQUEST/PUSH_REPLY (ifconfig/route/dhcp-option/peer-id/ping); ping magic 16B |
| NCP + compression framing | `OpenVpnDataCipher`/`OpenVpnPeerInfo`/`OpenVpnCompression` | IV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305 + IV_MTU/IV_PLAT/IV_PLAT_VER/IV_SSL_VER/IV_GUI_VER/`UV_*` (push-peer-info), server chốt `cipher` ở PUSH_REPLY; comp-lzo/stub-v2 framing (no-compress) |
| TCP packet framing (`proto tcp`) | `OpenVpnTcpFraming`/`OpenVpnTcpTransport` | mỗi gói prefix 16-bit big-endian length trên stream; seam F.2 `IPacketEncapsulator` |
| tun/tap device (`dev tun`/`dev tap`) | `OpenVpnTunChannel`/`OpenVpnTapChannel` | tun = IP packet → `IPacketChannel`; tap = Ethernet frame → `IEthernetChannel` (L2 fabric) |

## Trạng thái & ghi chú

- **Thuần client**, thuần protocol: không I/O, không server. Đọc spec/behavior từ nguồn OpenVPN (**không copy GPL source**).
- Build xanh cả `netstandard2.0` + `net8.0`. Codec dùng `System.Buffers.Binary.BinaryPrimitives` (có ở cả 2 TFM qua `System.Memory`), Span trong method non-async (an toàn C# 12). Wrap V2.c dùng `IncrementalHash.CreateHMAC` (HMAC nhiều đoạn, có ở cả 2 TFM) + `Crypto.AesCtr`; so tag bằng `FixedTimeEquals` tự viết (constant-time, không phụ thuộc `CryptographicOperations` của net5+). Data channel V2.d tái dùng `Crypto.Tls1Prf` (PRF) + `Crypto.AesGcmCipher` (AEAD) + `Crypto.AntiReplayWindow`; `Protect`/`TryUnprotect` non-async nên `stackalloc` nonce an toàn C# 12. `OpenVpnControlChannel` xử lý `SslStream` theo TFM giống [`TlsByteStream`](../TqkLibrary.VpnClient.Drivers.Sstp/Transport/TlsByteStream.cs): net5+ dùng `SslClientAuthenticationOptions` + `ct`; netstandard2.0 dùng overload cũ + cancel-bằng-dispose. Transport V2.g: `OpenVpnTcpTransport.SendAsync` lấy `packet.Span` tiêu thụ **trước** mọi `await` (không giữ Span qua await — an toàn C# 12); `OpenVpnTcpFraming` reassembly dùng `List<byte>` (zero-alloc là việc của Q.4, không phải đúng-sai); tun/tap channel `WriteIpPacketAsync`/`WriteFrameAsync` là method non-async trả `ValueTask` nên truyền `.Span` an toàn.
- Lộ trình V.2 đầy đủ ở [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.2; thiết kế ở [`.docs/06-openvpn.md`](../../.docs/06-openvpn.md).
