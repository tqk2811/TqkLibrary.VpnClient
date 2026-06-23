# lab/ikev2-native — VALIDATE LIVE driver V.1 IKEv2-native (strongSwan)

Lab Docker dựng **server IKEv2 strongSwan** (PSK + EAP-MSCHAPv2, ESP **tunnel** mode, Configuration
Payload cấp virtual IP/DNS) để **validate live** driver `TqkLibrary.VpnClient.Drivers.Ikev2`
([`Ikev2Connection`](../../src/TqkLibrary.VpnClient.Drivers.Ikev2/Ikev2Connection.cs#L35)). Client là binary
demo `.NET` self-contained, chạy trong container cùng bridge.

Khác lab [`l2tp-nonat`](../l2tp-nonat): **KHÔNG L2TP/PPP** — client IKEv2-native chở gói IP trần
trong ESP tunnel thẳng vào `IPacketChannel`. Carrier = **ESP-in-UDP/4500** (forced NAT-T float), nên
**KHÔNG cần raw socket / CAP_NET_RAW** (khác native-ESP proto-50 của P0.8c).

---

## 1. Topology (an toàn — như l2tp-nonat)

2 container trên một Docker bridge tùy biến `labnet`:

| Container | Vai trò |
|---|---|
| `lab-ikev2-server` | strongSwan 5.9.5 (charon) — IKEv2 PSK/EAP + ESP tunnel + CP virtual IP pool `10.40.0.0/24`. `cap_add: NET_ADMIN` (XFRM trong netns container, KHÔNG đụng VM). |
| `lab-ikev2-client` | `runtime-deps:8.0`, mount `./client-bin` (binary publish), `sleep infinity` — chạy demo bằng `docker exec`. KHÔNG cần CAP_NET_RAW. |

An toàn: **KHÔNG** `network_mode: host`, **KHÔNG** privileged-host — strongSwan đụng XFRM chỉ trong
netns container. **KHÔNG** publish cổng: test nội bộ bridge.

---

## 2. Transform khớp client (IkeProposals)

Server `ike=`/`esp=` phải khớp đề xuất của [`IkeClient` (V2)](../../src/TqkLibrary.VpnClient.Ipsec/Ike/V2/IkeProposals.cs):

| Pha | Client đề xuất | Server config |
|---|---|---|
| IKE (Phase 1) | AES-CBC-256 + PRF_HMAC_SHA2_256 + AUTH_HMAC_SHA2_256_128 + MODP2048 | `ike=aes256-sha256-modp2048!` |
| ESP (CHILD) | #1 AES-CBC-256 + HMAC-SHA2_256_128 (no PFS, no ESN); #2 AES-GCM-16-256 | `esp=aes256-sha256-noesn,aes256gcm16-noesn!` |

---

## 3. Publish client từ Windows host rồi đưa vào VM

```powershell
dotnet publish demo/Vpn2ProxyDemo -c Release -r linux-x64 --self-contained true -o lab/ikev2-native/client-bin
```

Copy `client-bin` sang VM tại `~/lab/ikev2-native/client-bin` (compose mount `./client-bin:/opt/client:ro`):

```bash
tar -cf - -C lab/ikev2-native client-bin | ssh <vm> 'cd ~/lab/ikev2-native && tar -xf - && chmod +x client-bin/Vpn2ProxyDemo'
# hoặc: scp -r lab/ikev2-native/client-bin <vm>:~/lab/ikev2-native/
```

> `client-bin/` (binary publish ~72MB ELF) **KHÔNG commit** (`.gitignore`) — tạo theo §3 trên từng máy.

---

## 4. Bring-up

```bash
cd ~/lab/ikev2-native
docker compose up -d --build         # build server image + chạy 2 container nền
docker compose ps
docker compose logs -f ikev2-server  # soi charon (handshake + CHILD_SA)
docker exec lab-ikev2-server ipsec statusall   # conn 'ikev2-native'/'ikev2-eap' + pool 10.40.0.0/24
```

---

## 5. Chạy client + quan sát THÀNH CÔNG

**Đường PSK** (mặc định):

```bash
docker exec -it lab-ikev2-client \
    /opt/client/Vpn2ProxyDemo dns --vpn 'ikev2://ikev2-server?psk=vpn'
#   tunnel up → assigned IP 10.40.0.x + dns; panel "Khả năng VPN" probe ICMP gateway + UDP DNS qua tunnel.
```

**Đường EAP-MSCHAPv2** (`--ikev2-eap`, user:pass khớp `ipsec.secrets`):

```bash
docker exec -it lab-ikev2-client \
    /opt/client/Vpn2ProxyDemo dns --vpn 'ikev2://testuser:testpass@ikev2-server?psk=vpn' --ikev2-eap
```

**Quan sát phía server (chạy song song):**

```bash
# IKE SA + CHILD SA: mong ESTABLISHED + INSTALLED, TUNNEL, ESP in UDP + bytes_i > 0
docker exec lab-ikev2-server ipsec statusall
#   THẤY: ikev2-native[N]: ESTABLISHED ... IKE proposal AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
#         ikev2-native{N}: INSTALLED, TUNNEL, ESP in UDP SPIs ... bytes_i (giải mã 2 chiều)
#         0.0.0.0/0 === 10.40.0.x/32  (virtual IP từ CP)

# DPD keepalive (driver gửi INFORMATIONAL rỗng mỗi ~20s):
docker compose logs ikev2-server | grep -i INFORMATIONAL
#   THẤY: parsed INFORMATIONAL request 2/3 [ ]  →  generating INFORMATIONAL response

# Teardown (demo thoát → DELETE IKE SA):
docker compose logs ikev2-server | grep -i "received DELETE"
#   THẤY: received DELETE for IKE_SA ... ESTABLISHED ⇒ DELETING ⇒ DESTROYING
```

---

## 6. Kết quả validate (2026-06-24)

| Tiêu chí | Kết quả |
|---|---|
| forced NAT-T 500→4500, IKE_SA_INIT, IKE_AUTH PSK, CP virtual IP/DNS, ESP tunnel | ✓ tunnel up, IP `10.40.0.1`, dns `1.1.1.1` |
| server `ESTABLISHED` + CHILD_SA `INSTALLED, TUNNEL, ESP in UDP` + `bytes_i > 0` | ✓ (proposal khớp, 176 bytes_i / 3 pkts) |
| ICMP gateway 2 chiều + UDP DNS qua tunnel | ✓ RTT 2ms + DNS query google.com qua 1.1.1.1 |
| DPD keepalive | ✓ INFORMATIONAL request 2/3 ↔ response |
| EAP-MSCHAPv2 | ✓ (sau khi **sửa bug MSK** — xem dưới) |
| teardown DELETE IKE SA | ✓ ESTABLISHED ⇒ DELETING ⇒ DESTROYING |

**BUG phát hiện + sửa (do live):** [`MsChapV2.DeriveMsk`](../../src/TqkLibrary.VpnClient.Crypto/MsChapV2.cs#L106)
đảo thứ tự send/recv key trong MSK 64-byte → EAP "succeeds" (`EAP method EAP_MSCHAPV2 succeeded, MSK
established`) nhưng IKEv2 AUTH-with-MSK (RFC 7296 §2.16) **fail trên gateway**
(`verification of AUTH payload with EAP MSK failed`). Test offline không bắt được vì harness responder
dùng **chung** `DeriveMsk` (đối xứng). Sửa = layout `send||recv` (dual của server's `recv||send`).

**Còn lại (residual, không chặn client):** live-rekey CHILD_SA / IKE SA (timer cứng ~90% lifetime =
~54 phút / ~7.2h — không khả thi trong phiên lab ngắn; client-initiated rekey + DELETE-SA-cũ đã test
offline). Plugin `eap-mschapv2` nằm trong gói **`libcharon-extauth-plugins`** (KHÔNG trong
`libcharon-extra-plugins` trên Ubuntu 22.04) — thiếu → `loading EAP_MSCHAPV2 method failed`.

---

## 7. Teardown

```bash
cd ~/lab/ikev2-native
docker compose down            # dừng + xóa container + network
docker image rm lab-ikev2-native:22.04   # (tùy) xóa image server
```
