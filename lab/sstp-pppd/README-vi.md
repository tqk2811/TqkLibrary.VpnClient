# lab/sstp-pppd — SSTP server bằng pppd CHUẨN + radvd (validate P1.1 IPv6-over-PPP)

> ✅ **CHẠY ĐƯỢC — đã validate live P1.1 (2026-06-23).** Client SSTP của repo lấy được địa chỉ
> **IPv6 GLOBAL** `fd00:dead:beef:0:<IID-IPV6CP>` qua SLAAC trên link PPP.

## 1. Vì sao có setup này (tách khỏi `lab/accel-ppp`)

`lab/accel-ppp` **HỎNG PPP network-phase**: `ipcp_layer_start` chạy nhưng accel-ppp KHÔNG bao
giờ gửi IPCP Configure-Request và ProtoRej mọi gói IPCP của client (lỗi FSM userspace của
accel-ppp trong VM này — đã loại trừ netns/iprange/IP-pool/mppe). Client repo đã **proven
đúng** (cùng `PppEngine` chạy ngon với VPN Gate L2TP). Vì cần một server có **IPv6 pool** để
validate **P1.1** (đa số VPN Gate chỉ IPv4), ta dựng setup MỚI dùng **pppd CHUẨN** (FSM khác
accel-ppp) qua [sorz/sstp-server](https://github.com/sorz/sstp-server) (SSTP server Python gọi
pppd) + **radvd** quảng bá prefix IPv6 → client SLAAC ra địa chỉ global.

## 2. Thành phần

| File | Vai trò |
|---|---|
| [`Dockerfile`](Dockerfile) | Ubuntu 24.04 + `ppp`(pppd) + `radvd` + `openssl` + `tcpdump` + `sstp-server` (pip, venv) |
| [`docker-compose.yml`](docker-compose.yml) | BRIDGED, `NET_ADMIN`+`NET_RAW`, `/dev/ppp`, publish **8443** (accel-ppp giữ 443) |
| [`entrypoint.sh`](entrypoint.sh) | tạo cert self-signed → chạy `sstpd -l 0.0.0.0 -p 8443 --local 10.30.0.1 --remote 10.30.0.0/24` |
| [`options.sstpd`](options.sstpd) | pppd options: `require-mschap-v2` / `+ipv6` / `ipv6cp-use-ipaddr` / `noccp` / mtu 1400 |
| [`chap-secrets`](chap-secrets) | `vpn * vpn *` (user `vpn` / pass `vpn`, mọi IP) |
| [`ipv6-up.sh`](ipv6-up.sh) | hook `/etc/ppp/ipv6-up.d/` — khi IPV6CP lên: gán `fd00:dead:beef::1/64` + (re)start radvd trên interface ppp động |
| [`ipv6-down.sh`](ipv6-down.sh) | hook `/etc/ppp/ipv6-down.d/` — dừng radvd khi phiên đóng (kill theo pidfile) |
| [`radvd.conf.tmpl`](radvd.conf.tmpl) | template radvd — hook thay `@IFACE@` = tên ppp; prefix `fd00:dead:beef::/64` On-link+Autonomous |

**crypto binding:** sstp-server CHỈ verify khi có `sstp-pppd-plugin.so` — ở đây **KHÔNG** cài plugin
⇒ server BỎ QUA crypto binding (client vẫn gửi, server accept Call-Connected). Đủ để validate
PPP network-phase + IPv6.

## 3. Chạy + test

```bash
# Trong VM (ssh vpnlab):
cd ~/lab/sstp-pppd
docker compose up -d --build
docker logs lab-sstp-pppd   # mong: "Listening on 0.0.0.0:8443..."
```

```powershell
# Trên Windows host (client .NET), <VM_IP> = IP của VM:
cd d:/IT/Csharp/Libraries/TqkLibrary.Vpn
# Stage 1 — IPv4 (IPCP):
dotnet run --project demo/Vpn2ProxyDemo -c Debug -- dns --vpn sstp://vpn:vpn@<VM_IP>:8443 --resolve example.com --dns-server 8.8.8.8
#   ⇒ "[sstp] tunnel up. assigned IP = 10.30.0.2"
# Stage 2 — IPv6 (P1.1, thêm --ipv6):
dotnet run --project demo/Vpn2ProxyDemo -c Debug -- dns --vpn sstp://vpn:vpn@<VM_IP>:8443 --resolve example.com --dns-server 8.8.8.8 --ipv6
#   ⇒ "ipv6 = fd00:dead:beef:0:..." (địa chỉ GLOBAL = P1.1 PASS)
```

> DNS probe có thể fail (lab không NAT internet) — không sao; `tunnel up` + IP/IPv6 được cấp là
> tiêu chí thành công.

## 4. Lưu ý vận hành

- **Restart sạch giữa các test.** pppd/radvd có thể leak tiến trình nếu phiên trước teardown bẩn;
  nhiều radvd instance trỏ interface đã chết làm **SSTP handshake fail không ổn định**. Khi gặp
  "SSTP connection closed during the handshake" lặp lại: `docker restart lab-sstp-pppd`. Hook
  `ipv6-down` (pidfile) đã dọn radvd đúng từ bản này, nhưng restart vẫn là cách chắc nhất.
- **KHÔNG chạy `tcpdump -i any` đồng thời với test** — snaplen lớn làm chậm pty của sstp-server
  → handshake fail. Soi gói bằng `tcpdump` chỉ khi KHÔNG cần tunnel up đồng thời, hoặc đọc pppd
  debug hex trong `docker logs`.
- `/proc/sys` là **read-only** trong container (do compose `sysctls:`); radvd báo warning
  `failed to set CurHopLimit ... Read-only file system` — **vô hại** (RA vẫn gửi, forwarding=1 đã
  set qua sysctls).

## 5. Phát hiện kèm theo (bug client đã sửa)

Lần validate này lộ một **bug thật trong client** ([`Icmpv6Ndisc`](../../src/TqkLibrary.VpnClient.Ethernet/Icmpv6Ndisc.cs)):
`OptionsOffsetFor(RouterAdvertisement)` và `BuildRouterAdvertisement` đặt options của RA ở byte
**20** thay vì **16** (RFC 4861 §4.2). Builder và parser cùng lệch nhất quán nên test round-trip nội
bộ vẫn xanh — nhưng `TryGetPrefixInformation` **fail trên RA THẬT** của radvd/Linux ⇒ SLAAC không
bao giờ tạo địa chỉ global (client rơi xuống DHCPv6 → không server → `ipv6 = (none)`). Đã sửa offset
về **16** + thêm test hồi quy bytes-RA-thật `RadvdRaDecodeTests`.
