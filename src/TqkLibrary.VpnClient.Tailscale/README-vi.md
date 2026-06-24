# TqkLibrary.VpnClient.Tailscale

Thư viện **control plane Tailscale (ts2021)** thuần .NET — hiện thực kênh điều khiển **Noise IK**
(`Noise_IK_25519_ChaChaPoly_BLAKE2s`) chạy HTTP/2 (h2c) bên trong, codec **khung ts2021**, các **message JSON
tailcfg** (RegisterRequest/RegisterResponse, MapRequest/MapResponse, Node), codec **key** (`mkey:`/`nodekey:`/`discokey:`)
và ánh xạ **netmap → WireGuardConfig đa-peer**. Đây là project protocol-level cho driver **V.7.5** (xem
[`.docs/11`](../../.docs/11-todo-roadmap.md) §V.7.5). **Data plane KHÔNG ở đây** — tái dùng nguyên
[WireGuard](../TqkLibrary.VpnClient.WireGuard) (V.3); project này chỉ thêm control plane sinh ra danh sách peer.

> **Trạng thái:** **control plane VALIDATE LIVE FULL ✓** vs **Headscale v0.29.1** (2026-06-24, lab
> [`lab/tailscale`](../../lab/tailscale/README-vi.md)): `/key` 200 → `/ts2021` **101** (Noise IK được Headscale chấp
> nhận) → `/machine/register` 200 **MachineAuthorized** (preauth key) → `/machine/map` **netmap** (2 node .NET đăng ký
> thật `100.64.0.19/.20`). **Tái dùng nguyên** [`NoiseSymmetricState`](../TqkLibrary.VpnClient.Crypto/Noise/NoiseSymmetricState.cs#L20)
> (BLAKE2s + HMAC-BLAKE2s + ChaCha20-Poly1305 32/12/16) + [`Curve25519DhGroup`](../TqkLibrary.VpnClient.Crypto/Noise/Curve25519DhGroup.cs#L15)
> + [`ChaCha20Poly1305Cipher`](../TqkLibrary.VpnClient.Crypto/Aead/ChaCha20Poly1305Cipher.cs#L18) (KHÔNG primitive mới).

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [WireGuard](../TqkLibrary.VpnClient.WireGuard)/[Nebula](../TqkLibrary.VpnClient.Nebula)):
các khối giao thức control-plane thuần. Khác mọi driver khác: control plane **HTTP/2 (h2c) trong kênh Noise IK** —
[`TailscaleControlClient`](Control/TailscaleControlClient.cs) (net5+) dùng `SocketsHttpHandler.ConnectCallback` trả về
[`Ts2021NoiseStream`](Control/Noise/Ts2021NoiseStream.cs#L24) (mã hóa record ChaCha20-Poly1305) cho `HttpClient` chạy
h2c prior-knowledge. Noise **IK** (responder static = `mkey:` lấy từ `/key`, biết trước → pre-message `<- s`) khác
WireGuard **IKpsk2** và Nebula **IX**.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | (gián tiếp qua WireGuard config) |
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | [`NoiseSymmetricState`](../TqkLibrary.VpnClient.Crypto/Noise/NoiseSymmetricState.cs#L20) (symmetric IK), [`Curve25519DhGroup`](../TqkLibrary.VpnClient.Crypto/Noise/Curve25519DhGroup.cs#L15) (X25519 DH + sinh key), [`ChaCha20Poly1305Cipher`](../TqkLibrary.VpnClient.Crypto/Aead/ChaCha20Poly1305Cipher.cs#L18) (record AEAD), [`Blake2s`](../TqkLibrary.VpnClient.Crypto/Noise/Blake2s.cs#L12)/[`HmacBlake2sPrf`](../TqkLibrary.VpnClient.Crypto/Noise/HmacBlake2sPrf.cs#L14) (hash + KDF) |
| Dùng | [WireGuard](../TqkLibrary.VpnClient.WireGuard) | [`WireGuardConfig`](../TqkLibrary.VpnClient.WireGuard/Config/WireGuardConfig.cs#L20)/[`WireGuardPeer`](../TqkLibrary.VpnClient.WireGuard/Config/WireGuardPeer.cs#L12) — netmap ánh xạ vào config đa-peer này |
| Được dùng bởi | [`Drivers.Tailscale`](../TqkLibrary.VpnClient.Drivers.Tailscale) (V.7.5) | driver chạy `LoginAsync` → netmap → WireGuardConfig → WireGuard data plane |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Tailscale/
├─ Keys/
│  └─ TailscaleKey.cs              # codec mkey:/nodekey:/discokey:/privkey: + lowercase hex 32B
├─ Control/
│  ├─ Noise/
│  │  ├─ Ts2021NoiseHandshake.cs   # Noise IK initiator (e,es,s,ss / e,ee,se) + prologue + Split
│  │  ├─ Ts2021Transport.cs        # record AEAD ChaCha20-Poly1305, nonce [4:12]=counter BE, AAD rỗng
│  │  ├─ Ts2021NoiseStream.cs      # Stream duplex record-frame + skip EarlyNoise 9B
│  │  ├─ Ts2021FrameCodec.cs       # khung [ver?][type][len BE] (initiation 5B / khác 3B)
│  │  └─ Ts2021FrameType.cs        # enum Initiation/Response/Error/Record
│  ├─ Messages/
│  │  ├─ OverTlsPublicKeyResponse.cs  # /key JSON {publicKey:"mkey:..."}
│  │  ├─ RegisterRequest.cs / RegisterResponse.cs / RegisterResponseAuth.cs  # /machine/register
│  │  ├─ MapRequest.cs / MapResponse.cs / TailscaleNode.cs  # /machine/map (netmap)
│  │  └─ Hostinfo.cs
│  ├─ ITailscaleControlClient.cs   # interface (driver phụ thuộc; fake netmap được offline)
│  ├─ TailscaleControlClient.cs    # orchestrator (net5+): /key -> noise -> register -> map
│  ├─ Ts2021Connector.cs           # HTTP upgrade /ts2021 + Noise IK -> Ts2021NoiseStream
│  └─ TailscaleControlException.cs
├─ Netmap/
│  └─ NetmapToWireGuardConfig.cs   # MapResponse -> WireGuardConfig đa-peer
└─ TailscaleCapability.cs          # CapabilityVersion=113 (= ControlProtocolVersion, = v1.80)
```

## Bảng type

| Type | Vai trò |
|------|---------|
| [`TailscaleKey`](Keys/TailscaleKey.cs#L18) | codec text key: `<prefix>` + lowercase hex 32B; `nodekey:` = WG pubkey nguyên |
| [`Ts2021NoiseHandshake`](Control/Noise/Ts2021NoiseHandshake.cs#L34) | Noise IK initiator: pre-message `<- s`, msg1 `e,es,s,ss`, msg2 `e,ee,se`, prologue `Tailscale Control Protocol v<N>` |
| [`Ts2021Transport`](Control/Noise/Ts2021Transport.cs#L20) | record cipher 1 chiều: ChaCha20-Poly1305, nonce `0^4‖counter(BE)` từ 0, AAD rỗng, max plaintext 4077B |
| [`Ts2021NoiseStream`](Control/Noise/Ts2021NoiseStream.cs#L24) | `Stream` duplex: write chia record ≤4077B, read ghép record; `SkipEarlyNoiseAsync` nuốt header 9B `\xff\xff\xffTS` |
| [`Ts2021FrameCodec`](Control/Noise/Ts2021FrameCodec.cs#L18) | khung big-endian: initiation `[ver u16][type=1][len u16]`, khác `[type][len u16]` |
| [`Ts2021Connector`](Control/Ts2021Connector.cs#L23) | `POST /ts2021` (Upgrade + `X-Tailscale-Handshake` base64 init) → 101 → Noise IK → `Ts2021NoiseStream` |
| [`TailscaleControlClient`](Control/TailscaleControlClient.cs) | (net5+) `/key` → noise → `/machine/register` (preauth) → `/machine/map` long-poll, đọc khung `[len LE u32][JSON]` |
| [`NetmapToWireGuardConfig`](Netmap/NetmapToWireGuardConfig.cs#L33) | self `Addresses`→tun IP; peer `Key`→WG pubkey, `AllowedIPs`→allowed-ips, `Endpoints`→endpoint (no-endpoint = skip) |
| [`RegisterRequest`](Control/Messages/RegisterRequest.cs#L13)/[`MapResponse`](Control/Messages/MapResponse.cs)/[`TailscaleNode`](Control/Messages/TailscaleNode.cs#L21) | DTO JSON PascalCase (Node.DERP rename) |

## Bảng chuẩn / RFC

| Chuẩn | Dùng ở |
|-------|--------|
| Tailscale ts2021 `control/controlbase` (Noise IK, khung 1/2/3/4, record nonce BE) | `Ts2021NoiseHandshake`/`Ts2021FrameCodec`/`Ts2021Transport` |
| Tailscale `control/controlhttp` (`/ts2021` upgrade, header `tailscale-control-protocol`/`X-Tailscale-Handshake`) | `Ts2021Connector` |
| Tailscale `tailcfg` (RegisterRequest/MapRequest/MapResponse/Node JSON) | `Control/Messages/*` |
| Tailscale `types/key` (`mkey:`/`nodekey:`/`discokey:` + hex) | `TailscaleKey` |
| Noise Protocol Framework §5 (IK pattern, SymmetricState) | `Ts2021NoiseHandshake` (tái dùng `NoiseSymmetricState`) |
| RFC 8439 (ChaCha20-Poly1305 IETF, nonce 12B) | `Ts2021Transport` |

## Luồng nội bộ (control login)

1. [`TailscaleControlClient.LoginAsync`](Control/TailscaleControlClient.cs) → `GET /key?v=113` → `mkey:` của control.
2. [`Ts2021Connector.ConnectAsync`](Control/Ts2021Connector.cs#L60): TCP → `POST /ts2021` (base64 [initiation](Control/Noise/Ts2021NoiseHandshake.cs#L91)) → 101 → đọc [response frame](Control/Noise/Ts2021FrameCodec.cs#L18) → [`ConsumeResponse`](Control/Noise/Ts2021NoiseHandshake.cs#L122) → [`Split`](Control/Noise/Ts2021NoiseHandshake.cs#L150) → `Ts2021NoiseStream` (+ skip EarlyNoise).
3. `HttpClient` (h2c qua `ConnectCallback`) → `POST /machine/register` ([RegisterRequest](Control/Messages/RegisterRequest.cs#L13), `Auth.AuthKey`) → `MachineAuthorized`.
4. `POST /machine/map` ([MapRequest](Control/Messages/MapRequest.cs#L13) Stream=true) → đọc khung `[len LE u32][JSON]` → [MapResponse](Control/Messages/MapResponse.cs).
5. [`NetmapToWireGuardConfig.Build`](Netmap/NetmapToWireGuardConfig.cs#L42) → `WireGuardConfig` đa-peer (driver dùng).

## Trạng thái & ghi chú

- **net5+ cho control client**: HTTP/2 h2c trên `Stream` tùy ý chỉ có từ net5 (`SocketsHttpHandler.ConnectCallback` +
  `Http2UnencryptedSupport`); netstandard2.0 KHÔNG có h2c nên [`TailscaleControlClient`](Control/TailscaleControlClient.cs)
  rào `#if NET5_0_OR_GREATER`. Codec/handshake/frame/mapping (phần lõi, tái dùng được) build cả 2 TFM.
- **`ControlProtocolVersion = CapabilityVersion = 113`**: Headscale đọc version ở initiation frame header làm
  `CapabilityVersion`, dưới `MinSupportedCapabilityVersion` (113 = v1.80) thì từ chối Noise upgrade (500). **Bài học live.**
- **System.Text.Json** (in-box net8, package cho ns2.0) — KHÔNG Newtonsoft. JSON wire = PascalCase (Go field verbatim),
  chỉ `Node.DERP` rename.
- **DERP relay + disco NAT-traversal = future** (peer phải reachable trực tiếp; lab dùng endpoint trực tiếp trên bridge).
