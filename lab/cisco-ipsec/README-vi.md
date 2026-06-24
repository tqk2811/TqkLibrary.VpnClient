# lab/cisco-ipsec — VALIDATE LIVE driver V.12 Cisco IPsec / EzVPN (strongSwan)

Lab Docker dựng **server Cisco-compatible remote-access strongSwan** (IKEv1 **Aggressive Mode** group PSK +
**XAUTH** user/pass + **Mode-Config** cấp virtual IP/DNS + ESP **tunnel** mode) để **validate live** driver
`TqkLibrary.VpnClient.Drivers.CiscoIpsec`
([`CiscoIpsecConnection`](../../src/TqkLibrary.VpnClient.Drivers.CiscoIpsec/CiscoIpsecConnection.cs#L35)). Client
là binary demo `.NET` self-contained, chạy trong container cùng bridge.

Khác lab [`ikev2-native`](../ikev2-native): **IKEv1 Aggressive Mode + XAUTH + Mode-Config** (không phải IKEv2
PSK/EAP + CP), nhưng cùng pattern **không L2TP/PPP** — client chở gói IP trần trong ESP tunnel thẳng vào
`IPacketChannel`. Carrier = **ESP-in-UDP/4500** (forced NAT-T float), nên **KHÔNG cần raw socket / CAP_NET_RAW**.

> ⚠️ **Bảo mật:** IKEv1 Aggressive Mode + group PSK là Phase 1 **yếu** (HASH_R của responder cho phép
> dictionary attack offline lên group PSK). strongSwan mặc định **từ chối** — lab bật tường minh
> `charon.i_dont_care_about_security_and_use_aggressive_mode_psk = yes`. Chỉ dùng để interop gateway
> Cisco-compatible legacy; production nên dùng IKEv2 hoặc L2TP/IPsec Main Mode.

---

## 1. Topology (an toàn — như ikev2-native)

2 container trên một Docker bridge tùy biến `labnet`:

| Container | Vai trò |
|---|---|
| `lab-cisco-server` | strongSwan (charon) — IKEv1 Aggressive + XAUTH + Mode-Config + ESP tunnel, pool virtual IP `10.41.0.0/24`. `cap_add: NET_ADMIN` (XFRM trong netns container, KHÔNG đụng VM). |
| `lab-cisco-client` | `runtime-deps:8.0`, mount `./client-bin` (binary publish), `sleep infinity` — chạy demo bằng `docker exec`. KHÔNG cần CAP_NET_RAW. |

An toàn: **KHÔNG** `network_mode: host`, **KHÔNG** privileged-host — strongSwan đụng XFRM chỉ trong
netns container. **KHÔNG** publish cổng: test nội bộ bridge.

---

## 2. Transform khớp client (IkeV1Proposals)

Server `ike=`/`esp=` phải khớp đề xuất của
[`IkeV1Proposals.Phase1Aggressive`](../../src/TqkLibrary.VpnClient.Ipsec/Ike/V1/IkeV1Proposals.cs#L37) +
[`Phase2Tunnel`](../../src/TqkLibrary.VpnClient.Ipsec/Ike/V1/IkeV1Proposals.cs#L87):

| Pha | Client đề xuất | Server config |
|---|---|---|
| IKE (Phase 1 Aggressive) | AES-CBC-256 + SHA1 + MODP-1024 (group 2) + XAUTHInitPreShared | `ike=aes256-sha1-modp1024!` |
| ESP (Quick Mode tunnel) | #1 AES-CBC-256 + HMAC-SHA1 (no PFS); #2 AES-GCM-16-256 | `esp=aes256-sha1,aes256gcm16!` |

Auth: `leftauth=psk` (server group PSK) + `rightauth=psk` (client group PSK hash) + `rightauth2=xauth-generic`
(XAUTH server tra **ipsec.secrets** — KHÔNG dùng `xauth-eap` đòi RADIUS). Plugin `xauth-generic` ở gói
**`libcharon-extauth-plugins`** (thiếu → `XAuth-EAP method backend not supported: radius`).

Credential mặc định demo: `?psk=groupsecret&group=vpngroup` + user:pass `testuser:testpass` (khớp `ipsec.secrets`).

---

## 3. Publish client từ Windows host rồi đưa vào VM

```powershell
dotnet publish demo/Vpn2ProxyDemo -c Release -r linux-x64 --self-contained true -o lab/cisco-ipsec/client-bin
```

Copy `client-bin` sang VM tại `~/lab/cisco-ipsec/client-bin` (compose mount `./client-bin:/opt/client:ro`):

```bash
tar -cf - -C lab/cisco-ipsec client-bin | ssh <vm> 'cd ~/lab/cisco-ipsec && tar -xf - && chmod +x client-bin/Vpn2ProxyDemo'
# hoặc: scp -r lab/cisco-ipsec/client-bin <vm>:~/lab/cisco-ipsec/
```

> `client-bin/` (binary publish ~72MB ELF) **KHÔNG commit** (`.gitignore`) — tạo theo §3 trên từng máy.

---

## 4. Bring-up

```bash
cd ~/lab/cisco-ipsec
docker compose up -d --build         # build server image + chạy 2 container nền
docker compose ps
docker compose logs -f cisco-server  # soi charon (Aggressive + XAUTH + CHILD_SA)
docker exec lab-cisco-server ipsec statusall   # conn 'cisco-ezvpn' + pool 10.41.0.0/24
```

---

## 5. Chạy client + quan sát THÀNH CÔNG

```bash
docker exec -it lab-cisco-client \
    /opt/client/Vpn2ProxyDemo dns --vpn 'cisco://testuser:testpass@cisco-server?psk=groupsecret&group=vpngroup'
#   tunnel up → assigned IP 10.41.0.1 + dns 1.1.1.1; panel "Khả năng VPN" probe ICMP gateway + UDP DNS qua tunnel.
```

**Quan sát phía server (chạy song song):**

```bash
docker compose logs cisco-server | grep -iE 'XAuth authentication|ESTABLISHED|CHILD_SA.*INSTALLED|assigning virtual IP'
#   THẤY: XAuth authentication of 'testuser' successful
#         IKE_SA cisco-ezvpn[N] state change: CONNECTING => ESTABLISHED
#         assigning virtual IP 10.41.0.1 to peer 'testuser'   (Mode-Config)
#         CHILD_SA cisco-ezvpn{N} established ... TS 0.0.0.0/0 === 10.41.0.1/32 ⇒ INSTALLED (TUNNEL)

# Teardown (demo thoát → DELETE ESP + ISAKMP SA):
docker compose logs cisco-server | grep -i "received DELETE"
```

---

## 6. Kết quả validate (2026-06-24)

| Tiêu chí | Kết quả |
|---|---|
| Aggressive Mode AG1/AG2 group PSK + NAT-T float 500→4500 | ✓ (HASH_R khớp, float UDP/4500) |
| XAUTH user/pass | ✓ `XAuth authentication of 'testuser' successful` |
| Mode-Config virtual IP/DNS | ✓ IP `10.41.0.1`, dns `1.1.1.1` |
| Quick Mode ESP tunnel-mode CHILD_SA | ✓ `INSTALLED`, `TS 0.0.0.0/0 === 10.41.0.1/32` |
| server IKE_SA `ESTABLISHED` | ✓ `CONNECTING => ESTABLISHED` |
| ICMP gateway 2 chiều + UDP DNS qua tunnel | ✓ RTT 2ms + DNS query google.com qua 1.1.1.1 (ESP decrypt 2 chiều) |
| teardown DELETE ESP + ISAKMP SA | ✓ DELETING |

**2 BUG phát hiện + sửa (do live — self-pair offline bỏ sót vì 2 phía cùng tự-khớp):**
1. **Message-ID:** `BuildXAuthReply`/`BuildXAuthAck`/`BuildModeConfigAck` tạo M-ID **mới** thay vì echo M-ID
   của request/set server gửi → strongSwan coi reply là TRANSACTION request mới (`queueing TRANSACTION
   request as tasks still active` → `ignoring TRANSACTION request, queue full`). Sửa: echo M-ID.
2. **IV chaining:** reply mã hóa bằng IV **derive lại** từ M-ID thay vì IV **chained** (RFC 2409 §5.5) →
   strongSwan `invalid HASH_V1 payload length, decryption failed?`. Sửa: `TransactionCipher(messageId)` cache
   1 cipher/M-ID dùng chung encrypt+decrypt trong exchange.
3. **Lab config:** `XAuth-EAP method backend not supported: radius` — thiếu plugin `xauth-generic` (chỉ có
   `xauth-eap` đòi RADIUS). Sửa: cài `libcharon-extauth-plugins` + `rightauth2=xauth-generic`.

**Còn lại (residual, không chặn client):** live-rekey Phase 2 ESP CHILD SA (timer cứng ~90% lifetime
Phase2 = ~54 phút — không khả thi trong phiên lab ngắn; client-initiated rekey đã test offline ở
[`IkeV1CiscoIpsecTests`](../../tests/TqkLibrary.VpnClient.Ipsec.Ike.Tests/IkeV1CiscoIpsecTests.cs) /
[`IkeV1QuickModeTests`](../../tests/TqkLibrary.VpnClient.Ipsec.Ike.Tests)). DPD keepalive (driver gửi IKE
R-U-THERE mỗi ~20s) test offline; live cần phiên >20s.

---

## 7. Teardown

```bash
cd ~/lab/cisco-ipsec
docker compose down -v          # dừng + xóa container + network + volume
docker image rm lab-cisco-ipsec:22.04   # (tùy) xóa image server
```
