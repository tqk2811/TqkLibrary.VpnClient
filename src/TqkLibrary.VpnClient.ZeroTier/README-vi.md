# TqkLibrary.VpnClient.ZeroTier

Thư viện **protocol ZeroTier V1 (x25519)** thuần .NET — hiện thực hai tầng giao thức ZeroTier ở mức codec:
**VL1** (transport: định danh **C25519**, dẫn xuất **địa chỉ 40-bit memory-hard**, gói UDP mã hóa+xác thực
**Salsa20/12 + Poly1305**, verb **HELLO/OK**) và **VL2** (virtual L2: **network-id 64-bit**, frame Ethernet trên verb
**FRAME/EXT_FRAME**, **network config dictionary**). Đây là project protocol-level cho driver **V.7.3**
([`Drivers.ZeroTier`](../TqkLibrary.VpnClient.Drivers.ZeroTier) đã hiện thực — xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.7.3).

> **Trạng thái:** **phase (a) + codec phase (b) XONG — VL1 OK peering + VL2 network join VALIDATE LIVE** (2026-06-24)
> — 46 test offline xanh, build xanh ns2.0 + net8. **(a)** Đối chiếu byte-exact với `zerotier-one` 1.16.2: address
> derivation **KAT 8 identity `zerotier-idtool` thật KHỚP** + VL1 **dearmor/re-seal HELLO thật BYTE-EXACT**. **(b)** vs
> `zerotier-one` **1.4.6** (Salsa20/12, pre-AES-GMAC-SIV): **HELLO⇄OK timestamp echo + NETWORK_CONFIG_REQUEST →
> controller-assigned IP + COM** (network join). **3 bug live** sửa qua phase b (Salsa20 block-boundary + OK(HELLO)
> reply + v4s/NUL dict — xem "Khác biệt" ở [`.docs/10`](../../.docs/10-codebase-architecture-and-flow.md)). **Tái dùng**
> [`Salsa20`](../TqkLibrary.VpnClient.Crypto/Salsa20.cs#L24) + [`Curve25519DhGroup`](../TqkLibrary.VpnClient.Crypto/Noise/Curve25519DhGroup.cs#L15)
> + BouncyCastle `Poly1305` + `SHA512` BCL — **không** viết lại crypto.

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [Nebula](../TqkLibrary.VpnClient.Nebula)/[Tinc](../TqkLibrary.VpnClient.Tinc)): các khối
giao thức + codec thuần, **không** I/O socket. VL1 packet codec là **seal/open đối xứng** (driver bơm datagram
vào/ra). Khác Nebula/WireGuard (Noise + AEAD trên `IPacketChannel` L3): ZeroTier là **overlay L2** — VL1 chở khung
Ethernet (VL2 FRAME) để driver ghép vào [Ethernet fabric](../TqkLibrary.VpnClient.Ethernet) (`IEthernetChannel`).
Cipher gói = **Salsa20/12 + Poly1305 phi-AEAD-chuẩn** (poly key = keystream block 0, tag 8B truncated trên ciphertext)
— KHÔNG phải ChaCha20-Poly1305 RFC 8439.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | [`Salsa20`](../TqkLibrary.VpnClient.Crypto/Salsa20.cs#L24) (VL1 /12 + identity hash /20), [`Curve25519DhGroup`](../TqkLibrary.VpnClient.Crypto/Noise/Curve25519DhGroup.cs#L15) (VL1 key agreement), BouncyCastle `Poly1305` (MAC gói), `SHA512` BCL (identity hash + KDF) |
| Được dùng bởi | [`Drivers.ZeroTier`](../TqkLibrary.VpnClient.Drivers.ZeroTier) (V.7.3 phase b) | driver lắp UDP transport + HELLO/OK + network-join quanh các codec này, ghép L2 fabric |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.ZeroTier/
├─ Identity/
│  ├─ ZeroTierIdentityCodec.cs        parse/encode identity (idtool-string "addr:0:pub[:priv]" + binary)
│  ├─ ZeroTierAddressDerivation.cs    memory-hard hash (SHA-512 + Salsa20/20 stream CBC-like 2MB + shuffle) → address (KAT live vs idtool)
│  └─ Models/
│     ├─ ZeroTierAddress.cs           địa chỉ node 40-bit (read/write/parse, reserved-rules: !=0, MSB!=0xff)
│     └─ ZeroTierIdentity.cs          pubkey 64B = Curve25519(32) ‖ Ed25519(32); privkey 64B tương ứng
├─ Vl1/
│  ├─ Vl1PacketCodec.cs               seal/open gói VL1 (_salsa20MangleKey + Salsa20/12 + Poly1305, cipher 0/1, DiscardToNextBlock, tag 8B — KAT live)
│  ├─ Vl1KeyDerivation.cs             shared key = SHA-512(X25519(myPriv, peerPub)); 32B đầu = Salsa20 key
│  ├─ HelloMessageCodec.cs            codec body verb HELLO (version + timestamp + identity nhúng)
│  ├─ OkMessageCodec.cs               OK common header (inReVerb‖inRePacketId) + OK(HELLO) (timestamp echo + versions + physical InetAddress)
│  ├─ InetAddressCodec.cs             ZeroTier InetAddress serialize (0x00 nil / 0x04 v4 / 0x06 v6 + port 2 BE)
│  ├─ Enums/
│  │  ├─ Vl1CipherSuite.cs            low 3 bit byte18: Poly1305None=0 / Salsa2012Poly1305=1 / None=2
│  │  └─ Vl1Verb.cs                   low 5 bit verb byte: NOP/HELLO/ERROR/OK/WHOIS/FRAME/EXT_FRAME/ECHO/NETWORK_CONFIG_REQUEST(0x0b)/NETWORK_CONFIG(0x0c)/MULTICAST_FRAME…
│  └─ Models/
│     ├─ Vl1Header.cs                 header 27B clear + verb byte (packetId/dest/src/cipher/MAC offsets)
│     ├─ HelloMessage.cs              POCO HELLO (protocol/version/timestamp/identity)
│     ├─ OkHelloMessage.cs            POCO OK(HELLO) (inReVerb/inRePacketId/timestampEcho/versions/physical)
│     └─ InetAddressValue.cs          POCO IP endpoint (nil/v4/v6 + port = prefix cho static IP)
└─ Vl2/
   ├─ Vl2FrameCodec.cs               codec body FRAME (networkId‖etherType‖frame — KHÔNG flags) + DeriveMac per-network
   ├─ Vl2ExtFrameCodec.cs            codec EXT_FRAME (networkId‖flags‖[COM]‖dstMac‖srcMac‖etherType‖frame)
   ├─ ZeroTierDictionary.cs          dict key=value text escape (=\e/NUL\0/CR\r/LF\n/\\) — container network config + COM
   ├─ NetworkConfigCodec.cs          NETWORK_CONFIG_REQUEST body + decode config dict (assigned IP I/v4s + routes RT + COM C/com + mtu)
   └─ Models/
      ├─ NetworkId.cs                network-id 64-bit (controller-address 40-bit ‖ index 24-bit)
      ├─ Vl2Frame.cs                 POCO khung VL2 (network/etherType/frameData + src/dst node address)
      ├─ Vl2ExtFrame.cs              POCO EXT_FRAME (network/flags/COM/dstMac/srcMac/etherType/frameData)
      └─ ZeroTierNetworkConfig.cs    POCO network config (network/assignedAddresses/routes/mtu/COM/name)
```

## Bảng type chính

| Type | Vai trò |
|------|---------|
| [`ZeroTierAddress`](Identity/Models/ZeroTierAddress.cs#L14) | địa chỉ node 40-bit — read/write 5B BE, parse 10-hex, `IsValid` (reserved-rules) |
| [`ZeroTierIdentity`](Identity/Models/ZeroTierIdentity.cs#L12) | identity = address + pubkey 64B (Curve25519‖Ed25519) + privkey tùy chọn |
| [`ZeroTierIdentityCodec`](Identity/ZeroTierIdentityCodec.cs#L20) | codec idtool-string + binary (round-trip public/private) |
| [`ZeroTierAddressDerivation`](Identity/ZeroTierAddressDerivation.cs#L30) | memory-hard hash → digest 64B + address; hashcash `digest[0]<17` |
| [`Vl1Header`](Vl1/Models/Vl1Header.cs#L20) | header VL1: packetId/dest/src 40-bit/cipher byte/MAC 8B/verb byte |
| [`Vl1PacketCodec`](Vl1/Vl1PacketCodec.cs#L31) | seal/open Salsa20/12 + Poly1305 (tamper/MAC reject) |
| [`Vl1KeyDerivation`](Vl1/Vl1KeyDerivation.cs#L16) | C25519 agreement → SHA-512 shared key (đối xứng 2 đầu) |
| [`HelloMessageCodec`](Vl1/HelloMessageCodec.cs#L13) | codec body HELLO |
| [`OkMessageCodec`](Vl1/OkMessageCodec.cs) | OK common header + OK(HELLO) (timestamp echo + physical InetAddress) |
| [`InetAddressCodec`](Vl1/InetAddressCodec.cs) | ZeroTier InetAddress serialize (nil/v4/v6 + port BE) |
| [`NetworkId`](Vl2/Models/NetworkId.cs#L10) | network-id 64-bit + controller-address split |
| [`Vl2FrameCodec`](Vl2/Vl2FrameCodec.cs#L17) | codec FRAME body (no flags) + `DeriveMac` per-network |
| [`Vl2ExtFrameCodec`](Vl2/Vl2ExtFrameCodec.cs) | codec EXT_FRAME (MAC tường minh + COM tùy chọn) |
| [`ZeroTierDictionary`](Vl2/ZeroTierDictionary.cs) | dict key=value text escape (container network config + COM) |
| [`NetworkConfigCodec`](Vl2/NetworkConfigCodec.cs) | NETWORK_CONFIG_REQUEST + decode config dict (assigned IP/routes/COM/mtu) |

## Bảng chuẩn / behavior ZeroTier (clean-room — đọc spec/prose, KHÔNG copy BSL source)

| Hạng mục | Giá trị (ZeroTier V1, x25519) |
|----------|-------------------------------|
| Identity pubkey | 64B = Curve25519(32, ECDH) ‖ Ed25519(32, sign); type byte `0x00` |
| Address | 40-bit (5B) = `digest[59..64]` của memory-hard hash; reserved: `!=0`, MSB `!=0xff` |
| Memory-hard hash (KAT live) | `digest = SHA-512(pubkey)`; Salsa20/**20** **key=`digest[0..32]` iv=`digest[32..40]`** trên **1 stream LIÊN TỤC**; genmem **2MB** **CBC-like** (block0 = encrypt zeros, block i = encrypt copy block i−64); shuffle **131072 vòng** (đọc 2 uint64 **big-endian**, idx1=`n1%8`, idx2=`n2%262144`, swap 8B digest↔genmem, **re-encrypt digest mỗi vòng**); hashcash `digest[0] < 17`; addr=`digest[59..64]` |
| VL1 header (27B clear + verb) | `[0..8)` packetId/IV ‖ `[8..13)` dest 40-bit ‖ `[13..18)` src 40-bit ‖ `[18]` `FFCCCHHH` = flags(bit6-7)+cipher(bit3-5)+hops(bit0-2) ‖ `[19..27)` MAC 8B ‖ `[27]` verb byte (flags 3 + verb 5) |
| VL1 key mangle (`_salsa20MangleKey`) | per-packet key = shared key XOR header: `[0..18)`↔IV+dest+src, `[18]`↔flags (hops `0xf8`-mask), `[19],[20]`↔packet size LE, `[21..32)` giữ nguyên — bind key vào header, tách A→B / B→A |
| VL1 cipher | **cipher 0 `C25519_POLY1305_NONE`** (HELLO — payload KHÔNG mã hóa) / **cipher 1 `Salsa2012Poly1305`** (data + **OK** — mã hóa); Salsa20/**12** key=mangled, nonce=packetId 8B; poly key = keystream block 0 (32B đầu); **payload cipher bắt đầu ở block KẾ — bỏ 32B đuôi block0** (`DiscardToNextBlock`, Salsa20 ZeroTier block-granular); Poly1305 trên section (verb‖payload), tag truncate 8B đầu. **(1.6+ negotiate AES-GMAC-SIV cipher 3 — client chưa hiện thực, advertise proto v10 để peer giữ Salsa20/12)** |
| VL1 key | per-node = `SHA-512(X25519(myCurve25519Priv, peerCurve25519Pub))` = `ECC::agree`; 32B đầu = Salsa20 key |
| VL1 verb | NOP=0, **HELLO=1**, ERROR=2, OK=3, WHOIS=4, RENDEZVOUS=5, FRAME=6, EXT_FRAME=7, MULTICAST_FRAME=0x0E |
| HELLO body | `protocolVer(1) ‖ major(1) ‖ minor(1) ‖ revision(2 BE) ‖ timestamp(8 BE) ‖ identity(addr5‖type1‖pub64‖privlen1=0) ‖ nil-InetAddress(1=0x00)` — cipher 0 (chưa có session key) |
| VL2 network-id | 64-bit = controller-address(40-bit) ‖ index(24-bit); in 16-hex |
| VL2 FRAME body | `networkId(8) ‖ etherType(2 BE) ‖ frameData` (**KHÔNG flags byte** — verified live); src/dst node address từ VL1 header |
| VL2 EXT_FRAME body | `networkId(8) ‖ flags(1) ‖ [COM nếu flags&0x01] ‖ dstMac(6) ‖ srcMac(6) ‖ etherType(2 BE) ‖ frameData` (MAC tường minh + COM tùy chọn) |
| VL2 network config | `OK(NETWORK_CONFIG_REQUEST)`/`NETWORK_CONFIG`: `networkId(8) ‖ dictLen(2 BE) ‖ dict` (dict key=value text: assigned IP `I`/`v4s`, COM `C`/`com`, routes `RT`, mtu) |
| VL2 MAC | `DeriveMac` clean-room: low 40-bit = node address, top octet seed từ network-id. **LƯU Ý**: node thật dùng **random per-node tap MAC** (KHÔNG khớp DeriveMac) ⇒ data plane cần học MAC qua MULTICAST_FRAME/ARP |

## Luồng seal/open VL1 (mangle key + Salsa20/12 + Poly1305)

1. **Seal** [`Vl1PacketCodec.Seal`](Vl1/Vl1PacketCodec.cs#L40): ghi header clear (byte 18 `FFCCCHHH`) → `MangleKey`
   (shared key XOR header) → Salsa20/12 init (mangled key, nonce=packetId) → keystream block 0 = poly key (32B) →
   cipher 1: mã hóa `verb‖payload`; cipher 0 (HELLO): giữ nguyên → Poly1305(section) truncate 8B vào MAC `[19..27)`.
2. **Open** [`Vl1PacketCodec.Open`](Vl1/Vl1PacketCodec.cs#L81): đọc header clear → cùng `MangleKey` + key-stream →
   tính lại MAC trên section, so khớp (fixed-time) **trước** khi giải mã (cipher 1) / trả verbatim (cipher 0).

## Trạng thái & ghi chú

- **Phase (a) protocol**: XONG — **address + VL1 VALIDATE LIVE byte-exact vs zerotier-one 1.16.2**. Live (lab/zerotier)
  lộ **7 bug interop self-pair offline KHÔNG bắt**: **address** 6 bug (key/iv split đảo, genmem CBC-like stream-liên-tục,
  re-encrypt digest mỗi vòng, index big-endian, idx2 % 262144, 131072 vòng) → KAT 8 identity idtool KHỚP; **VL1** thiếu
  `_salsa20MangleKey` + cipher-0 no-encrypt + byte-18 layout `FFCCCHHH` → dearmor + re-seal HELLO thật BYTE-EXACT.
- **Codec phase (b) + VALIDATE LIVE VL1 OK peering + VL2 network join 2026-06-24** (vs zerotier-one **1.4.6** — Salsa20/12;
  1.6+ negotiate AES-GMAC-SIV chưa hiện thực): thêm `OkMessageCodec`/`InetAddressCodec`/`ZeroTierDictionary`/
  `NetworkConfigCodec`/`Vl2ExtFrameCodec`; **HELLO⇄OK timestamp echo + NETWORK_CONFIG_REQUEST → assigned IP + COM**. **3 bug
  live** (self-pair offline KHÔNG bắt): **(1)** Salsa20/12 payload bắt đầu ở block KẾ (`DiscardToNextBlock` — bỏ 32B đuôi
  block0; decrypt cipher-1 ra rác dù MAC pass; KAT HELLO cipher-0 không bắt), **(2)** OK(HELLO) reply path (controller chờ
  OK(HELLO) của ta mới xử lý request), **(3)** dict parse (assigned IP key text `v4s` không phải binary `I`; value chứa raw
  NUL không được coi là terminator; OK in-re gap 2B). **FRAME body bỏ flags byte** (design ngầm có flags — SAI).
- **CÒN LẠI — data plane VL2 ICMP live**: node thật dùng **random per-node tap MAC** (KHÔNG derivable từ ZT address) ⇒
  cần **MULTICAST_FRAME (verb 0x0e)** cho broadcast/ARP học MAC peer. EXT_FRAME egress 2-way proven offline. Driver runtime
  = [`Drivers.ZeroTier`](../TqkLibrary.VpnClient.Drivers.ZeroTier) (XONG — VL1 OK peering + network join live).
- **Cert/identity P384 (ZeroTier 2.x)** KHÔNG hiện thực — mới làm V1 x25519 (Curve25519/Ed25519/Salsa20) như roadmap.
