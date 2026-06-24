# lab/nebula — validate LIVE handshake V.7.1 Nebula (Noise IX, interop binary thật)

Lab kiểm chứng **protocol layer V.7.1** (project [`TqkLibrary.VpnClient.Nebula`](../../src/TqkLibrary.VpnClient.Nebula)) bằng cách
bắt tay **Noise IX** với binary **`nebula` THẬT** (Slack, github.com/slackhq/nebula) — bắt bug interop mà self-pair
offline không thấy (bài học WireGuard construction-string / IKEv2 MSK).

Khác các lab trước (publish→scp→docker exec, 2 container bridge): Nebula handshake-interop chạy **đơn giản** —
1 process `nebula` làm responder/lighthouse + 1 harness `.NET` làm initiator, cùng host (host network).

---

## ⚑ Kết quả validate LIVE (2026-06-24, nebula v1.9.5)

**Handshake Noise IX interop HOÀN TOÀN THÀNH CÔNG — nebula THẬT chấp nhận + trả lời, ta giải mã + verify cert.**

| Tầng | Trạng thái | Bằng chứng |
|------|-----------|-----------|
| **Cert codec offline** | ✅ byte-perfect | parse `ca.crt`/`client.crt` thật; **re-marshal details == signed bytes (100==100)**; fingerprint khớp `nebula-cert print` (`03a4fc…`) |
| **Ed25519 verify** | ✅ | CA self-sign valid + client cert sig valid against CA pubkey (`846427…`) |
| **X25519 key ↔ cert** | ✅ | private key (`NEBULA X25519 PRIVATE KEY`) derive ra đúng pubkey trong cert |
| **Handshake stage 1 (ta→nebula)** | ✅ | nebula log `Handshake message received certName=client … style:ix_psk0 vpnIp=192.168.100.5` — **KHÔNG** `invalid`/`failed to decrypt` |
| **Handshake stage 2 (nebula→ta)** | ✅ | nebula `Handshake message sent stage:2`; harness **giải mã thành công** (`ConsumeResponse` OK) |
| **Responder cert verify** | ✅ | recombine static pubkey (Noise `s` token) → verify Ed25519 against CA → `name='lighthouse'` valid |
| **Transport keys** | ✅ | Split crossed keys; `ResponderIndex` harness decode == `responderIndex` trong log nebula |
| **Data plane (ICMP, stretch)** | ⏳ tunnel-lifecycle | gói data AEAD gửi đi; nebula trả `RecvError` (tunnel half-open bị tear-down vì harness 1-shot exit) — **KHÔNG** lỗi decrypt/spoof trong log ⇒ crypto đúng, còn lại là việc của driver phase (b) |

**Chứng minh dứt khoát**: mọi byte của Noise IX khớp nebula — construction string `Noise_IX_25519_AESGCM_SHA256`,
prologue rỗng (MixHash empty), thứ tự token (`e,s` plaintext msg1 / `e,ee,se,s,es` AEAD msg2), thứ tự DH ee/se/es,
payload protobuf `NebulaHandshake`, cert strip-pubkey + recombine. **First-run success, KHÔNG có bug interop phải sửa**
(nhờ verify spec wire-format kỹ trước + cert codec đã đối chiếu cert thật offline trước khi mở socket).

---

## ⚑ Kết quả validate LIVE FULL-TUNNEL phase b (2026-06-24, nebula v1.9.5)

**Driver [`Drivers.Nebula`](../../src/TqkLibrary.VpnClient.Drivers.Nebula) lên tunnel với nebula THẬT — ICMP 2 CHIỀU qua overlay, 0 bug data-plane.**

Khác phase a (1 process responder `tun.disabled`, chỉ handshake): phase b dựng **2 container bridge** (`docker-compose.yml`) — nebula làm
**lighthouse + peer với `tun` ENABLED** (overlay `192.168.100.1/24`, CAP_NET_ADMIN + `/dev/net/tun`) + client `.NET` (driver
`Drivers.Nebula`, overlay `192.168.100.5` qua userspace `TcpIpStack` — KHÔNG cần tun) trên cùng `labnet`. Client `--vpn /lab/client.nebula`.

| Tầng | Trạng thái | Bằng chứng |
|------|-----------|-----------|
| **Handshake live (driver)** | ✅ | nebula `Handshake message received certName=client stage:1` + `sent stage:2 responderIndex=399895568`; driver `handshake stage-2 consumed; transport keys derived` → `state -> Connected` |
| **Tunnel alive** | ✅ | nebula `Tunnel status tunnelCheck="map[method:passive state:alive]"` (timer giữ tunnel sống) |
| **ICMP 2 chiều (data plane)** | ✅✅ | demo `Gateway nội bộ 192.168.100.1 (ICMP reachable, RTT 4 ms)`; **tcpdump nebula1**: `192.168.100.5 > 192.168.100.1: ICMP echo request seq 1` + `192.168.100.1 > 192.168.100.5: ICMP echo reply seq 1` — request đến + reply đi qua overlay nebula thật |
| **UDP decrypt** | ✅ (route ngoài overlay) | nebula giải mã gói UDP-DNS của ta (`fwPacket={8.8.8.8 192.168.100.5 53 …}`) nhưng drop vì `local IP is not in list of handled local IPs` (8.8.8.8 ngoài overlay — lab isolated, KHÔNG lỗi decrypt) ⇒ data-plane AEAD đúng cả UDP |

**Chứng minh dứt khoát data-plane**: message packet `Type=Message` AEAD đúng byte-for-byte với nebula —
AAD = 16-byte header (`RemoteIndex`=responderIndex routing, `MessageCounter`=counter), nonce = `0^4 ‖ counter(8 BE)`,
AES-256-GCM key hướng initiator/responder từ Noise `Split`. **First-run success — 0 bug data-plane** (layout đã chứng minh ở phase a
stretch; phase b chỉ thêm tunnel lifecycle giữ tunnel sống cho 2 chiều). `RecvError` đầu phiên = gói data-đầu đến trước khi nebula
bind tunnel xong (1-shot race, driver log + recover) — KHÔNG phải bug.

---

## Chạy lại

Trên VM lab (`ssh vpnlab`, Docker + internet), thư mục `~/nebula-lab/`:

```bash
# 1. Tải nebula + nebula-cert (binary Go tĩnh, KHÔNG cần Go toolchain)
VER=v1.9.5
curl -sSL -o nebula.tar.gz \
  "https://github.com/slackhq/nebula/releases/download/${VER}/nebula-linux-amd64.tar.gz"
tar xzf nebula.tar.gz   # → ./nebula ./nebula-cert

# 2. Sinh CA + cert (xem gen-certs.sh)
NEBULA_CERT=./nebula-cert bash gen-certs.sh

# 3. Chạy nebula responder (Docker host-network, tun disabled ⇒ không cần root tun)
docker run -d --name nebula-responder --network host -v ~/nebula-lab:/lab:ro -w /lab \
  alpine:3.20 sh -c "cp /lab/responder.yml /tmp/r.yml; exec /lab/nebula -config /tmp/r.yml"

# 4. Publish harness (trên máy dev) rồi scp vào VM:  dotnet publish -c Release -r linux-x64 -o publish
#    (harness/ csproj ref Nebula + Crypto; xem harness/Program.cs)
./harness . 127.0.0.1:4242
#    → "SUCCESS: real nebula accepted our Noise IX handshake and we completed it."

# 5. Kiểm log nebula:  docker logs nebula-responder | grep -i handshake
# 6. Dọn:  docker rm -f nebula-responder
```

### Phase b — full-tunnel ICMP 2 chiều (driver `Drivers.Nebula`)

```bash
# (sau bước 1–2 ở trên: nebula binary + ca.crt/lighthouse.*/client.* đã sẵn trong ~/nebula-lab/)
# 3. Publish demo linux-x64 (máy dev) → copy vào ~/nebula-lab/client-bin/
dotnet publish demo/Vpn2ProxyDemo -c Release -r linux-x64 --self-contained -o publish
scp -r publish/* vpnlab:~/nebula-lab/client-bin/

# 4. Dựng lab 2 container (nebula tun + client) bằng compose
docker compose up -d                      # nebula-peer (tun overlay 192.168.100.1) + nebula-client

# 5. Chạy client demo: handshake → tunnel → probe ICMP gateway nội bộ (= overlay nebula)
docker exec nebula-client sh -c 'cd /app && ./Vpn2ProxyDemo dns --vpn /lab/client.nebula'
#    → "Gateway nội bộ: 192.168.100.1 (ICMP reachable, RTT 4 ms)"

# 6. (tuỳ chọn) bằng chứng overlay: tcpdump trên nebula1 thấy echo request đến + reply đi
docker exec nebula-peer sh -c 'apk add tcpdump >/dev/null 2>&1; timeout 18 tcpdump -i nebula1 -n icmp'

# 7. Dọn:  docker compose down -v ; rm -rf client-bin
```

## Ghi chú
- `responder.yml`: `tun.disabled: true` ⇒ nebula KHÔNG cần root/CAP_NET_ADMIN, vẫn listen UDP 4242 + handshake (phase a).
- `responder-tun.yml` + `docker-compose.yml` (phase b): `tun.disabled: false` ⇒ nebula dựng overlay `192.168.100.1` trả ICMP
  (cần CAP_NET_ADMIN + `/dev/net/tun`). Client KHÔNG cần tun (userspace `TcpIpStack`). `client.nebula` trỏ ca/cert/key + endpoint.
- 2 host static biết IP nhau (hoặc responder là lighthouse) **handshake trực tiếp**, KHÔNG cần lighthouse discovery
  cho lab 2-node (nebula chấp nhận handshake từ mọi cert ký bởi CA tin cậy).
- Cert/key/binary **KHÔNG commit** (xem `.gitignore`) — chỉ commit config + script + harness source.
