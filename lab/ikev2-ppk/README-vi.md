# lab/ikev2-ppk — VALIDATE LIVE IKEv2 PPK (RFC 8784, post-quantum preshared key)

Lab Docker dựng **server IKEv2 strongSwan 5.9.13 có PPK** (swanctl) để validate live nhánh
**PPK (RFC 8784)** của driver `TqkLibrary.VpnClient.Drivers.Ikev2` + `PpkConfiguration`
(demo cờ `--ppk`/`--ppk-id`/`--ppk-mandatory`, hoặc `VpnClientBuilder.UseIkev2WithPpk`).

Khác lab [`ikev2-native`](../ikev2-native/README-vi.md):
- **ubuntu:24.04 (strongSwan 5.9.13)** — PPK có từ strongSwan **5.9.6+**; bản 5.9.5 của 22.04 (lab
  ikev2-native) KHÔNG hỗ trợ PPK.
- Cấu hình bằng **swanctl.conf** (vici), KHÔNG ipsec.conf/starter — PPK là tính năng swanctl-only.
- Còn lại giữ nguyên topology AN TOÀN: 2 container trên bridge `labppknet`, KHÔNG host-net,
  KHÔNG privileged-host ⇒ strongSwan đụng XFRM chỉ trong netns container, không phá mạng VM.

---

## 1. Topology

| Container | Vai trò |
|---|---|
| `lab-ikev2-ppk-server` | strongSwan 5.9.13 (charon + swanctl) — IKEv2 PSK + **PPK** + ESP tunnel + CP virtual IP pool `10.40.0.0/24`. `cap_add: NET_ADMIN`. |
| `lab-ikev2-ppk-client` | `runtime-deps:8.0`, mount `./client-bin`, `sleep infinity` — chạy demo bằng `docker exec`. |

## 2. Transform + PPK khớp client

| Mục | Client | Server (swanctl.conf) |
|---|---|---|
| IKE | AES-CBC-256 + PRF/AUTH-SHA2-256 + MODP2048 | `proposals = aes256-sha256-modp2048` |
| ESP | #1 AES-CBC-256+SHA2-256, #2 AES-GCM-16-256 (noesn) | `esp_proposals = aes256-sha256-noesn,aes256gcm16-noesn` |
| PSK | `?psk=vpn` | secret `ike-vpn { secret = "vpn" }` |
| **PPK** | `--ppk 0x0011…0011 --ppk-id ppk1` | secret `ppk-lab { id = ppk1; secret = 0x0011…0011 }` + conn `ppk_id = ppk1` |

PPK secret 32 byte hex PHẢI trùng hai phía; PPK_ID client gửi = `[0x01]"ppk1"` (PPK_ID_OPAQUE, RFC 8784 §4.1).

## 3. Publish client + bring-up

```powershell
dotnet publish demo/Vpn2ProxyDemo -c Release -r linux-x64 --self-contained true -o lab/ikev2-ppk/client-bin
```
```bash
tar -cf - -C lab/ikev2-ppk client-bin | ssh <vm> 'cd ~/lab/ikev2-ppk && tar -xf - && chmod +x client-bin/Vpn2ProxyDemo'
cd ~/lab/ikev2-ppk && docker compose up -d --build          # KHÔNG restart sau khi sửa config — xem lưu ý dưới
```

> ⚠️ **Config bake vào image** (COPY, không mount): sửa `swanctl.conf`/`strongswan.conf` xong PHẢI
> `docker compose up -d --build` (hoặc `docker exec … swanctl --load-all` cho riêng swanctl.conf) —
> `docker compose restart` chạy lại bản CŨ trong image. (Xem lab ikev2-native cùng gotcha.)

## 4. Chạy client + quan sát

```bash
PPK=0x0011223344556677889900112233445566778899001122334455667788990011
# PPK optional (fallback PSK nếu server không PPK):
docker exec lab-ikev2-ppk-client /opt/client/Vpn2ProxyDemo dns --vpn 'ikev2://ikev2-ppk-server?psk=vpn' --ppk "$PPK" --ppk-id ppk1
# PPK mandatory (abort nếu server không echo USE_PPK):
docker exec lab-ikev2-ppk-client /opt/client/Vpn2ProxyDemo dns --vpn 'ikev2://ikev2-ppk-server?psk=vpn' --ppk "$PPK" --ppk-id ppk1 --ppk-mandatory
# server:
docker exec lab-ikev2-ppk-server swanctl --list-conns   # 'ikev2-ppk' + 'ppk: ppk1'
docker compose logs ikev2-ppk-server | grep -iE 'USE_PPK|PPK_ID|PPK required'
```

---

## 5. Trạng thái validate (2026-07-08) — ĐANG DỞ (interop responder-side)

| Bước | Kết quả |
|---|---|
| Client build 2 TFM + offline test (`IkePpkTests` 12 case, prf+ KAT) | ✓ |
| Client gửi **USE_PPK** trong IKE_SA_INIT | ✓ server **echo** `N(USE_PPK)` |
| Client mix PPK (`prf+`) + gửi **PPK_IDENTITY** trong IKE_AUTH | ✓ server **parse** `N(PPK_ID)` |
| Server áp PPK + IKE_AUTH thành công + tunnel up | ✗ **CHƯA** — xem dưới |

**Bức tường (chưa giải):** strongSwan 5.9.13 responder **parse được** `N(PPK_ID)` nhưng bước xử lý PPK
báo `PPK required but no PPK_IDENTITY received` (khi `ppk_required=yes`) / không áp PPK → verify AUTH bằng
SK_pi **thuần** → `MAC mismatched` (khi `ppk_required=no`). Client tính AUTH bằng SK_pi **đã mix PPK** ⇒
lệch. Đã thử mọi encoding secret `id`: `ppk1` (ID_FQDN), `@#70706b31` (ID_KEY_ID "ppk1"),
`@#0170706b31` (kèm type-octet), `%any` — đều không khiến strongSwan áp PPK. Nghi giới hạn/nuance
**responder-side roadwarrior** (client IDi=0.0.0.0 do Config Payload). Cần đào strongSwan source hoặc thử
site-to-site (IDi cố định) để mở khóa.

**BUG client đã phát hiện + sửa (nhờ đối chiếu RFC khi debug live):**
[`IkeKeyMaterial.WithPpk`](../../src/TqkLibrary.VpnClient.Ipsec/Ike/V2/IkeKeyMaterial.cs#L107) dùng
`prf(PPK, SK_x)` — RFC 8784 §3 yêu cầu **`prf+(PPK, SK_x)`** = `prf(PPK, SK_x | 0x01)` (thiếu byte đếm
`0x01`). Test offline đối xứng (responder harness cùng dùng `WithPpk`) không bắt được — giống bug
`MsChapV2.DeriveMsk` (đã sửa nhờ lab ikev2-native). Đã sửa dùng `PrfPlus.Expand`.

## 6. Cấu trúc

```
lab/ikev2-ppk/
├─ docker-compose.yml   # 2 service bridge: ikev2-ppk-server (swanctl) + dotnet-client
├─ Dockerfile           # ubuntu:24.04 + strongswan + strongswan-swanctl
├─ swanctl.conf         # IKEv2 PSK + PPK (ppk_id/ppk_required) + ESP tunnel + CP pool
├─ strongswan.conf      # charon (install_routes/virtual_ip + filelog ike=3)
├─ entrypoint.sh        # charon (bg) → swanctl --load-all → wait (foreground)
└─ README-vi.md         # file này
```
