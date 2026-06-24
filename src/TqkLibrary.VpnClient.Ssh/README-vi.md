# TqkLibrary.VpnClient.Ssh

Lớp **protocol thuần** của **VPN-over-SSH** (OpenSSH `-w` tun) — một **client SSH-2 transport tối thiểu** (RFC 4251/4253/4252/4254 + extension OpenSSH) đủ để mở channel `tun@openssh.com` và chở gói IP. Các codec/state-machine chạy trên **một `IByteStreamTransport` đã có sẵn** (không tự mở socket), để driver [`Drivers.Ssh`](../TqkLibrary.VpnClient.Drivers.Ssh) ráp thành tunnel sống. Gồm 4 mảng: (1) **wire + binary packet** (kiểu dữ liệu RFC 4251 §5 + đóng gói gói RFC 4253 §6 với seam cipher); (2) **2 cipher AEAD OpenSSH** (`chacha20-poly1305@openssh.com` + `aes256/128-gcm@openssh.com`); (3) **transport handshake** (version exchange + KEXINIT + curve25519 KEX + ed25519 host-key); (4) **userauth + channel tun** (publickey-ed25519/password + framing L3 `tun@openssh.com`). Viết **clean-room từ RFC + OpenSSH PROTOCOL** (KHÔNG dùng thư viện SSH ngoài, KHÔNG copy code).

## Vị trí kiến trúc

`PROTOCOL`-layer (như [`Vtun`](../TqkLibrary.VpnClient.Vtun)/[`Tinc`](../TqkLibrary.VpnClient.Tinc)/[`N2n`](../TqkLibrary.VpnClient.N2n)): codec thuần + state-machine handshake, không tự sở hữu socket. Ref **chỉ** `Abstractions` (`IByteStreamTransport`) + `Crypto` (tái dùng tối đa primitive đã có — X25519, Ed25519, AES-GCM, ChaCha20). Tái dùng F.4/Crypto chính là lý do tự viết khả thi thay vì kéo một thư viện SSH đầy đủ.

- **Wire/binary packet** [`SshPacketCodec`](Wire/SshPacketCodec.cs): đóng/mở gói SSH binary packet RFC 4253 §6 (`length || padding_length || payload || random padding`) trên `IByteStreamTransport` — cleartext **trước NEWKEYS** rồi qua seam [`ISshPacketCipher`](Cipher/ISshPacketCipher.cs); seqno 32-bit **mỗi chiều**; reader buffered vắt liền ranh giới cleartext→encrypted (không mất byte). [`SshWriter`](Wire/SshWriter.cs)/[`SshReader`](Wire/SshReader.cs): kiểu dữ liệu RFC 4251 §5 (byte/boolean/uint32/uint64/string/mpint/name-list — big-endian, mpint sign-byte). [`SshRandom`](Wire/SshRandom.cs): random crypto cross-TFM (internal). [`SshMessageNumber`](Wire/Enums/SshMessageNumber.cs): số message transport/userauth/connection + ECDH 30/31.
- **Cipher** [`ChaCha20Poly1305OpenSshCipher`](Cipher/ChaCha20Poly1305OpenSshCipher.cs): `chacha20-poly1305@openssh.com` (OpenSSH PROTOCOL.chacha20poly1305) — K_2=256-bit đầu (payload + poly key), K_1=256-bit sau (mã hóa **riêng** field length); nonce = seqno uint64 BE; poly key = keystream K_2 counter-0 32B đầu, payload từ block counter 1; MAC = Poly1305 trên `enc-length || enc-payload`, **constant-time check trước khi decrypt**; dùng [`ChaCha20`](../TqkLibrary.VpnClient.Crypto/ChaCha20.cs) (djb gốc). [`AesGcmOpenSshCipher`](Cipher/AesGcmOpenSshCipher.cs): `aes256/128-gcm@openssh.com` (RFC 5647) — 4-byte length **cleartext làm AAD**; IV 12-byte = 4 fixed || 8 invocation-counter **tăng mỗi gói** (KHÔNG phải seqno); tái dùng `AesGcmCipher`. Seam [`ISshPacketCipher`](Cipher/ISshPacketCipher.cs): `BlockSize`/`TagLength`/`LengthIsEncrypted`/`Seal`/`ReadLength`/`Open`.
- **Transport** [`SshVersionExchange`](Transport/SshVersionExchange.cs): banner RFC 4253 §4.2 (V_C/V_S không CRLF, bỏ qua dòng pre-banner, trả `Leftover` để đẩy lại vào codec). [`SshKexInit`](Transport/SshKexInit.cs): codec KEXINIT RFC 4253 §7.1 + `Negotiate` theo thứ tự ưu tiên client (offer kex `curve25519-sha256`(+`@libssh.org`), hostkey `ssh-ed25519`, cipher `chacha20-poly1305@openssh.com` + `aes256-gcm@openssh.com`). [`Curve25519KeyExchange`](Transport/Curve25519KeyExchange.cs): KEX `curve25519-sha256` RFC 8731/5656 §4 — X25519 ephemeral (tái dùng [`Curve25519DhGroup`](../TqkLibrary.VpnClient.Crypto/Noise/Curve25519DhGroup.cs)); `H = SHA256(V_C||V_S||I_C||I_S||K_S||Q_C||Q_S||K)` (mỗi field SSH-string trừ K=mpint); KDF letter A..F RFC 4253 §7.2 (mở rộng K1||K2 cho khóa chacha 64B). [`SshEd25519HostKey`](Transport/SshEd25519HostKey.cs): parse K_S (`string "ssh-ed25519" || string pub32`), verify chữ ký trên H (tái dùng [`Ed25519Signer`](../TqkLibrary.VpnClient.Crypto/Noise/Ed25519Signer.cs)), SHA256 fingerprint cho TOFU pinning.
- **Auth + channel** [`SshUserAuth`](Auth/SshUserAuth.cs): RFC 4252 userauth — service-request `ssh-userauth`; publickey ed25519 (ký `session_id || USERAUTH_REQUEST đến hết public-key blob`, RFC 4252 §7) hoặc password. [`SshTunFraming`](Channel/SshTunFraming.cs): framing L3 `tun@openssh.com` — trong channel-data `string`, payload = `uint32 address_family || ip_packet` (AF chọn theo nibble version IP); **KHÔNG có field packet_length dẫn đầu** (`Overhead`=4). [`SshTunAddressFamily`](Channel/Enums/SshTunAddressFamily.cs) `INET=2`/`INET6=24`; [`SshTunChannelMode`](Channel/SshTunChannelMode.cs) `POINTOPOINT=1`/`ETHERNET=2`.
- **Orchestrator** [`SshClient`](SshClient.cs): điều phối toàn bộ state machine trên 1 `IByteStreamTransport` + [`SshClientOptions`](SshClientOptions.cs).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IByteStreamTransport` (codec/handshake chạy trên byte-stream do driver cấp) |
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | **`ChaCha20`** (djb, cho `chacha20-poly1305@openssh.com`) + **`AesGcmCipher`** (`aes*-gcm@openssh.com`) + **`Curve25519DhGroup`** (X25519 KEX) + **`Ed25519Signer`** (host-key verify + publickey auth); SHA-256/Poly1305 lấy từ BCL/Crypto |
| Được dùng bởi | [Drivers.Ssh](../TqkLibrary.VpnClient.Drivers.Ssh) | ráp codec/handshake thành tunnel runtime (TCP I/O + tun channel + facade) |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Ssh/
├─ Wire/
│  ├─ SshWriter.cs            Ghi kiểu dữ liệu RFC 4251 §5 (byte/uint32/uint64/string/mpint/name-list, big-endian, mpint sign-byte)
│  ├─ SshReader.cs            ref struct đọc kiểu dữ liệu RFC 4251 §5
│  ├─ SshRandom.cs            Fill random crypto cross-TFM (internal)
│  ├─ SshPacketCodec.cs       Binary packet RFC 4253 §6: WritePacketAsync/ReadPacketAsync, cleartext→ISshPacketCipher, seqno/chiều, PushBackBytes
│  └─ Enums/SshMessageNumber.cs  Số message SSH (transport/userauth/connection + ECDH 30/31)
├─ Cipher/
│  ├─ ISshPacketCipher.cs            Seam: BlockSize/TagLength/LengthIsEncrypted/Seal/ReadLength/Open
│  ├─ ChaCha20Poly1305OpenSshCipher.cs  chacha20-poly1305@openssh.com (K_2 payload+poly / K_1 length-only, nonce seqno BE, Poly1305 constant-time)
│  └─ AesGcmOpenSshCipher.cs         aes256/128-gcm@openssh.com (length=AAD, IV 4-fixed‖8-invocation-counter)
├─ Transport/
│  ├─ SshVersionExchange.cs   Banner RFC 4253 §4.2 (V_C/V_S, bỏ pre-banner, trả Leftover)
│  ├─ SshKexInit.cs           Codec KEXINIT RFC 4253 §7.1 + CreateClientDefault + Negotiate (ưu tiên client)
│  ├─ Curve25519KeyExchange.cs   KEX curve25519-sha256 (X25519 + H=SHA256(…) + KDF letter A..F + K1‖K2)
│  └─ SshEd25519HostKey.cs    Parse K_S + VerifyExchangeHash + Sha256Fingerprint (TOFU)
├─ Auth/
│  └─ SshUserAuth.cs          RFC 4252: service-request + publickey ed25519 / password
├─ Channel/
│  ├─ SshTunFraming.cs        tun@openssh.com L3: uint32 AF‖ip_packet (AF-only, KHÔNG packet_length; Overhead 4)
│  ├─ SshTunChannelMode.cs    POINTOPOINT=1 / ETHERNET=2
│  └─ Enums/SshTunAddressFamily.cs  INET=2 / INET6=24 (hằng OpenSSH, không phải AF_* host)
├─ SshClient.cs              State machine: version → KEXINIT → curve25519 KEX → ed25519 verify → NEWKEYS → userauth → tun channel; SendIpPacketAsync/RunReceiveLoopAsync/CloseAsync
├─ SshClientOptions.cs       Username + PrivateKeyEd25519/Password + RemoteTunUnit (AnyTunUnit 0x7fffffff) + ClientId + HostKeyValidator
└─ SshProtocolException.cs   Lỗi negotiation/auth/channel
```

## Luồng nội bộ (handshake — [`SshClient.ConnectAsync`](SshClient.cs#L63))

1. **Version exchange** ([`SshVersionExchange.ExchangeAsync`](Transport/SshVersionExchange.cs#L39)): trao banner V_C/V_S; `Leftover` đẩy lại vào [`SshPacketCodec.PushBackBytes`](Wire/SshPacketCodec.cs#L49).
2. **KEXINIT** ([`SshKexInit.CreateClientDefault`](Transport/SshKexInit.cs#L52) → [`Negotiate`](Transport/SshKexInit.cs#L121)): gửi I_C, đọc I_S, chốt kex/hostkey/cipher 2 chiều (bắt buộc `curve25519-sha256`).
3. **curve25519 KEX** ([`Curve25519KeyExchange.ComputeSharedAndHash`](Transport/Curve25519KeyExchange.cs#L47)): gửi Q_C (KEX_ECDH_INIT), nhận K_S/Q_S/signature (KEX_ECDH_REPLY) → tính K + exchange hash H.
4. **Host-key verify** ([`SshEd25519HostKey.Parse`](Transport/SshEd25519HostKey.cs#L33) + [`VerifyExchangeHash`](Transport/SshEd25519HostKey.cs#L47)): verify chữ ký ed25519 trên H; nếu có `HostKeyValidator` (TOFU pin) thì gọi với [`Sha256Fingerprint`](Transport/SshEd25519HostKey.cs#L58).
5. **NEWKEYS** ([`BuildCipher`](SshClient.cs#L147)): gửi/đợi NEWKEYS rồi cài cipher 2 chiều — letter IV c→s `'A'`/s→c `'B'`, key c→s `'C'`/s→c `'D'` ([`DeriveKey`](Transport/Curve25519KeyExchange.cs#L87)); set vào [`SetOutboundCipher`](Wire/SshPacketCodec.cs#L43)/[`SetInboundCipher`](Wire/SshPacketCodec.cs#L46).
6. **userauth** ([`SshUserAuth.RequestUserAuthServiceAsync`](Auth/SshUserAuth.cs#L41) → [`AuthenticatePublicKeyAsync`](Auth/SshUserAuth.cs#L58) / [`AuthenticatePasswordAsync`](Auth/SshUserAuth.cs#L104)): publickey ed25519 nếu có `PrivateKeyEd25519`, ngược lại password.
7. **CHANNEL_OPEN `tun@openssh.com`** (`OpenTunChannelAsync` trong [`SshClient.cs`](SshClient.cs#L173)): point-to-point ([`SshTunChannelMode.PointToPoint`](Channel/SshTunChannelMode.cs)) + `RemoteTunUnit`; chờ CHANNEL_OPEN_CONFIRMATION.
8. **Data plane**: [`SendIpPacketAsync`](SshClient.cs#L219) bọc gói IP qua [`SshTunFraming`](Channel/SshTunFraming.cs#L24) (AF-only) + CHANNEL_DATA; [`RunReceiveLoopAsync`](SshClient.cs#L240) bơm channel-data → `InboundIpPacket`, tiêu WINDOW_ADJUST, gọi link-loss khi CHANNEL_CLOSE/EOF/DISCONNECT; [`CloseAsync`](SshClient.cs#L302) gửi CHANNEL_CLOSE.

## Bảng chuẩn / RFC (clean-room, KHÔNG copy code)

| Khía cạnh | Nguồn | Ghi chú |
|-----------|-------|---------|
| Kiến trúc + kiểu dữ liệu wire | RFC 4251 §5 | byte/boolean/uint32/uint64/string/mpint/name-list (big-endian; mpint sign-byte) |
| Binary packet + version + KEXINIT + KEX/KDF + NEWKEYS | RFC 4253 §4.2/§6/§7.1/§7.2/§7.3 | đóng gói length+padding; banner V_C/V_S; negotiate; H/KDF letter A..F |
| Userauth (publickey/password) | RFC 4252 §5/§7 | service `ssh-userauth`; sign `session_id‖request` cho publickey |
| Connection (channel) | RFC 4254 §5 | CHANNEL_OPEN/DATA/WINDOW_ADJUST/CLOSE/EOF |
| ECDH key exchange | RFC 5656 §4 | message KEX_ECDH_INIT/REPLY (30/31) |
| curve25519-sha256 KEX | RFC 8731 | X25519 ephemeral + abort all-zero shared (RFC 7748 §6) |
| AES-GCM ciphers | RFC 5647 + OpenSSH PROTOCOL §1.6 | `aes*-gcm@openssh.com`: length cleartext=AAD, IV invocation-counter |
| chacha20-poly1305 cipher | OpenSSH PROTOCOL.chacha20poly1305 | K_1 length-only / K_2 payload+poly; nonce seqno BE; ChaCha20 djb (KHÁC IETF RFC 8439) |
| Poly1305 / ChaCha20 djb gốc | RFC 8439 (Poly1305) / draft-strombergson (ChaCha20 KAT) | MAC + keystream; ChaCha20 **stateful** (KHÔNG layout IETF) |
| Algorithm names / extension @openssh.com | RFC 8709 + OpenSSH PROTOCOL §2.3 | ssh-ed25519; `tun@openssh.com`; SSH_TUNMODE/SSH_TUN_AF |
| tun framing L3 | OpenSSH PROTOCOL §2.3 | **AF-only**: `uint32 AF‖ip_packet`; "uint32 packet length" = length-prefix của SSH `string` (xem live-found bug) |

## Trạng thái & ghi chú

- **OFFLINE**: 31 test [`Ssh.Tests`](../../tests/TqkLibrary.VpnClient.Ssh.Tests) — wire codec (gồm vector mpint RFC 4253 §5), 2 cipher (`chacha20-poly1305@openssh.com` + `aes256-gcm@openssh.com`) round-trip/tamper/wrong-seqno, packet codec round-trip cleartext + cả 2 cipher qua loopback byte-stream, tun framing AF-only round-trip. Build XANH ns2.0 + net8.
- **VALIDATE LIVE** (qua [`Drivers.Ssh`](../TqkLibrary.VpnClient.Drivers.Ssh) tới **OpenSSH 9.6p1** thật): full handshake + KEX + NEWKEYS + cipher `chacha20-poly1305@openssh.com` (host key verify, cipher byte-exact vs sshd) + publickey ed25519 ACCEPTED + `tun@openssh.com` open + ICMP 2 chiều. Chi tiết ở [`.docs/10`](../../.docs/10-codebase-architecture-and-flow.md) §9 + lab [`ssh`](../../lab/ssh).
- ⚠️ **tun framing AF-only (live-found bug)**: trong channel-data `string`, payload **chỉ** là `uint32 address_family || ip_packet` — KHÔNG có field `packet_length` dẫn đầu (phần "uint32 packet length" ở PROTOCOL §2.3 chính là length-prefix của SSH `string`, đã bị `ReadString` tiêu thụ). Self-pair offline bỏ sót (server giả lập cùng framing 2 đầu); chỉ live vs sshd thật mới lộ. `Overhead`=4.
- **CHƯA làm (stretch)**: thêm thuật toán **KEX/cipher/auth** (hostkey rsa/ecdsa, KEX `diffie-hellman-group*`, cipher aes-ctr + hmac EtM, auth keyboard-interactive); **rekey giữa phiên** (`SSH_MSG_KEXINIT` mid-session); **tap mode L2** (`SSH_TUNMODE_ETHERNET` → `IEthernetChannel`). Khóa riêng OpenSSH PEM (hiện chỉ nhận seed ed25519 32-byte trần) parse ở phía demo, ngoài project này.
