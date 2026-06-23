# lab Q.1 — Docker server VPN để VALIDATE LIVE driver TqkLibrary.VpnClient

> ✅ **P1.1 (IPv6-over-PPP/SLAAC) đã VALIDATE LIVE** qua setup riêng [`sstp-pppd/`](sstp-pppd/README-vi.md)
> (sstp-server + **pppd CHUẨN** + radvd) — KHÔNG phải `accel-ppp/` (accel-ppp hỏng PPP
> network-phase trong VM này). SSTP client lấy địa chỉ IPv6 **global** `fd00:dead:beef:0:...` qua
> SLAAC. Xem [`sstp-pppd/README-vi.md`](sstp-pppd/README-vi.md).

> ⚠️ **`accel-ppp/` + `strongswan/` vẫn là BẢN NHÁP.** Khung lab để bring-up & **tinh chỉnh
> live**. `accel-ppp` HỎNG PPP network-phase (không gửi IPCP ConfReq — lỗi FSM userspace, đã
> loại trừ netns/iprange/IP-pool/mppe); dùng [`sstp-pppd/`](sstp-pppd/README-vi.md) thay thế cho
> mọi việc cần PPP network-phase (IPCP/IPV6CP). Mọi chỗ nghi ngờ đánh dấu `# CHECK:` + liệt kê ở
> [§8 Điểm cần tinh chỉnh live](#8-điểm-không-chắc-cần-tinh-chỉnh-live).

Mục tiêu: thay server công khai (VPN Gate flaky) bằng server VPN chạy **trong VM Ubuntu
Server 24.04 (VMware)**, để validate LIVE các mục **P1.1 / P1.2 / P1.3 / P1.7 / P0.8c** của
2 driver live (**SSTP**, **L2TP/IPsec**). Client C#/.NET chạy trên **Windows host** (ngoài VM),
nối tới IP của VM.

---

## 1. Kiến trúc lab

```
   Windows host (Hyper-V TẮT — để chạy Intel XTU)
   ├─ demo/Vpn2ProxyDemo (client .NET, chạy Admin nếu cần raw socket)
   │        │  sstp://vpn:vpn@<VM_IP>      l2tp://vpn:vpn@<VM_IP>?psk=vpn
   │        ▼
   └─ VMware (VMM cổ điển, độc lập Hyper-V)
        └─ VM Ubuntu Server 24.04  (IP = <VM_IP>, host-only/bridged)
             └─ Docker engine
                  ├─ lab-accel-ppp   (host net): SSTP 443/tcp, L2TP 1701/udp, PPTP 1723/tcp
                  │                               + IPv6 pool + RA/SLAAC trên ppp  ← P1.1(2)
                  └─ lab-strongswan  (host net): IKEv1 PSK 500/4500/udp + ESP proto-50
                                                 (rekey ngắn P1.3 / no-NAT P0.8c)
```

- **accel-ppp** đảm nhận PPP + L2TP-control(1701) + SSTP(443) + PPTP(1723) và **IPv6 pool +
  Router Advertisement** trên link ppp (validate P1.1(2) SLAAC-over-PPP, P1.7 multi-session).
- **strongSwan** chỉ lo **IKEv1 + ESP transport** bọc UDP/1701 của L2TP. Tách 3 conn cho
  rekey-ngắn (P1.3) và no-NAT (P0.8c).
- Cả 2 dùng `network_mode: host` (ESP proto-50, GRE proto-47, nhiều cổng UDP/TCP — bridge NAT
  không forward sạch + NAT phá NAT-D; xem comment đầu `docker-compose.yml`).

---

## 2. Yêu cầu VM + mạng VMware

### 2.1 Hyper-V phải TẮT (ràng buộc Intel XTU)
User tắt Hyper-V để chạy **Intel XTU** ⇒ VMware chạy **VMM cổ điển** (không qua nền tảng
Hyper-V/WHP). Vì vậy **không dùng được WSL2 / Docker-Desktop** trên Windows host (cả 2 cần
Hyper-V/WSL2). Giải pháp: **cài Docker engine TRONG VM Linux** — không vướng Hyper-V.

Kiểm tra Hyper-V đã tắt (PowerShell Admin trên Windows host):
```powershell
bcdedit /enum | Select-String hypervisorlaunchtype   # mong: Off
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All  # State: Disabled
```

### 2.2 Mạng VMware — KHUYẾN NGHỊ host-only hoặc bridged, TRÁNH NAT
| Chế độ | Dùng được? | Ghi chú |
|---|---|---|
| **Host-only** (khuyến nghị) | ✅ | Subnet riêng host↔VM (vmnet1). Bật được IPv6. ESP/GRE/proto-50 đi thẳng host↔VM. Tốt cho P0.8c (no-NAT thật giữa host và VM). |
| **Bridged** | ✅ | VM có IP cùng LAN. Cũng tốt; cẩn thận firewall LAN chặn proto lạ. |
| **NAT** (VMware NAT) | ⚠️ TRÁNH | VMware NAT thường **không forward proto-50/47** và **phá NAT-D** → P0.8c không validate được; L2TP/IPsec có thể vẫn lên nhờ float-4500 nhưng đó KHÔNG phải kịch bản no-NAT. |

**Lấy IP VM (host-only)** — trong VM:
```bash
ip -4 addr show         # tìm IP của ens33/ens160 thuộc subnet vmnet host-only, vd 192.168.x.y
ip -6 addr show         # nếu host-only bật IPv6, có IPv6 link-local/ULA cho outer-IPv6 (P1.2)
```
Ghi nhớ IP này = `<VM_IP>` dùng cho client.

> **Outer IPv6 (P1.2):** muốn client nối tới VM qua **IPv6**, host-only vmnet phải bật IPv6
> (VMware: Virtual Network Editor → vmnet host-only → enable IPv6, hoặc gán ULA tĩnh cho VM
> NIC). Khi đó `<VM_IP>` là một địa chỉ IPv6 và client phải resolve/nối theo AAAA.

---

## 3. Chuẩn bị VM (một lần)

```bash
# 3.1 Docker engine + compose v2 (KHÔNG dùng Docker-Desktop)
sudo apt update
sudo apt install -y docker.io docker-compose-v2
#   (hoặc script chính chủ: curl -fsSL https://get.docker.com | sudo sh)
sudo usermod -aG docker "$USER"   # rồi logout/login để dùng docker không cần sudo

# 3.2 Module kernel ppp (accel-ppp cần /dev/ppp)
sudo modprobe ppp_generic
echo ppp_generic | sudo tee /etc/modules-load.d/ppp.conf

# 3.3 Forwarding + accept_ra trên HOST (VM), persist
sudo tee /etc/sysctl.d/99-vpnlab.conf >/dev/null <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.accept_ra=2
EOF
sudo sysctl --system

# 3.4 (tuỳ chọn) mở firewall VM nếu ufw bật
sudo ufw allow 443/tcp; sudo ufw allow 1723/tcp
sudo ufw allow 500/udp; sudo ufw allow 4500/udp; sudo ufw allow 1701/udp
# ESP proto-50 / GRE proto-47 không phải cổng: ufw cần rule riêng hoặc tắt ufw khi test P0.8c.
```

---

## 4. Bring-up

```bash
cd lab
sudo docker compose up -d --build       # build 2 image rồi chạy nền

# Xem log từng service
sudo docker compose logs -f accel-ppp
sudo docker compose logs -f strongswan

# Trạng thái
sudo docker compose ps
```

Kiểm tra nhanh trong container:
```bash
# accel-ppp: liệt kê session đang kết nối
sudo docker exec -it lab-accel-ppp accel-cmd show sessions   # CHECK: cổng cli 2000
# strongSwan: trạng thái SA
sudo docker exec -it lab-strongswan ipsec statusall
```

Teardown:
```bash
sudo docker compose down            # giữ volume cert
sudo docker compose down -v         # xoá luôn cert SSTP
```

---

## 5. Trỏ CLIENT (Windows host) tới VM

Build demo trên Windows host (thư mục repo, KHÔNG trong VM):
```powershell
dotnet build demo/Vpn2ProxyDemo
```

Cú pháp client (xem `demo/Vpn2ProxyDemo/CommandModules/Models/VpnTarget.cs`): URI
`scheme://user:pass@host[:port][?psk=...]`. Subcommand = **hành động**: `dns`, `proxy-server`,
`http-request`.

```powershell
# --- SSTP (TCP/443, PPP/MS-CHAPv2) ---
dotnet run --project demo/Vpn2ProxyDemo -- dns          --vpn sstp://vpn:vpn@<VM_IP>
dotnet run --project demo/Vpn2ProxyDemo -- http-request --vpn sstp://vpn:vpn@<VM_IP> --url http://checkip.amazonaws.com

# --- L2TP/IPsec (IKEv1 PSK + L2TP + PPP/MS-CHAPv2) ---
dotnet run --project demo/Vpn2ProxyDemo -- dns          --vpn l2tp://vpn:vpn@<VM_IP>?psk=vpn
dotnet run --project demo/Vpn2ProxyDemo -- proxy-server --vpn l2tp://vpn:vpn@<VM_IP>?psk=vpn
```

> ⚠️ **Quyền Admin:** mục **P0.8c** (native ESP proto-50, raw socket) yêu cầu client chạy
> **quyền Administrator** (Windows) — mở PowerShell "Run as administrator". Các mục khác
> (SSTP, L2TP qua NAT-T 4500) **không** cần admin.

> ⚠️ **Cert SSTP self-signed:** server lab dùng cert self-signed ⇒ client phải **chấp nhận
> cert bất kỳ**. `SstpDriver`/`UseSstp` có tham số `RemoteCertificateValidationCallback`
> (xem roadmap P0 + project `Drivers.Sstp`). **Demo hiện không truyền callback** ⇒ theo
> ghi chú P0 "không truyền ⇒ chấp nhận mọi cert" nên thường OK; nếu demo từ chối cert,
> phải sửa demo truyền callback always-true (KHÔNG nằm trong phạm vi tạo file lab này).

---

## 6. BẢNG ÁNH XẠ — mục P × kịch bản lab × cách quan sát thành công

> ⚠️ Nhiều mục cần client **bật cờ/đường mã tương ứng**. Demo `Vpn2ProxyDemo` nay **đã có cờ
> `--ipv6`** (bật `enableIpv6` cho SSTP/L2TP — P1.1). Còn lại **chưa wire**: `HonestFirst` +
> `UseL2tpIpsec(IRawIpTransportFactory)` cho **P0.8c** (cần thêm flag tạm hoặc test integration
> gọi thẳng driver). Lab này chuẩn bị **phía SERVER**; cột "client cần" ghi rõ phần còn thiếu.

| Mục | Service + kịch bản lab | Client cần | Cách quan sát THÀNH CÔNG |
|---|---|---|---|
| **P1.1** IPv6-in-tunnel (SLAAC-over-PPP) | accel-ppp `[ipv6-pool]` + `[ipv6-nd]` RA trên ppp | **`--ipv6`** (đã có): bật `enableIpv6` → P1.1(2) gửi Router Solicitation, nhận RA, suy địa chỉ global | Trong tunnel có địa chỉ **global-scope** `fd00:dead:beef:…`. Log driver kiểu "obtained global IPv6 …" / `TunnelConfig.AssignedAddressV6` ≠ link-local. Server: `accel-cmd show sessions` thấy IPv6 cấp; `docker exec lab-accel-ppp ip -6 addr` thấy prefix trên ppp. Ping6 từ client tới `fd00:dead:beef::1`. |
| **P1.2** Outer IPv6 (nối server qua IPv6) | accel-ppp/strongSwan trên VM có **IPv6 host-only** | client resolve theo AAAA / `AddressFamilyPreference=IPv6` | Client SSTP/L2TP **nối được khi `<VM_IP>` là địa chỉ IPv6**. IKE NAT-D + ESP/UDP chạy trên IPv6. `docker compose logs` thấy peer IPv6. |
| **P1.3** Rekey Phase1 IKEv1 | strongSwan `l2tp-psk-rekey` (`ikelifetime=3m`) | driver L2TP/IPsec (rekey Phase1 đã có sẵn trong code) | Giữ tunnel chạy >5–10 phút: **không rớt** khi qua mốc 3m. `ipsec statusall` thấy ISAKMP SA **mới** thay SA cũ; data plane không gián đoạn (proxy/ping liên tục). |
| **P1.7** Multi-session L2TP | accel-ppp (nhiều call/tunnel) + strongSwan `uniqueids=no` | `OpenAdditionalSessionAsync` / `IVpnConnection.OpenSessionAsync` (đã có trong code) | 2 PPP/IPCP độc lập trên 1 IKE/IPsec SA → **2 địa chỉ** khác nhau. `accel-cmd show sessions` thấy ≥2 session cùng user trên cùng tunnel. |
| **P0.8c** Native ESP proto-50 (no-NAT) | strongSwan `l2tp-psk-nonat` (`forceencaps=no`) + lab **không-NAT** (host-only/bridged) | client **Admin** + `UseL2tpIpsec(IRawIpTransportFactory)` (HonestFirst) | IKE giữ **UDP/500** (không float 4500); ESP chạy **proto-50** thật. Trong VM: `sudo tcpdump -ni any proto 50` thấy gói ESP (không phải UDP/4500). `ipsec statusall` thấy SA **không** `NAT-T`/`encap`. |

### 6.1 Bật đúng conn strongSwan cho từng test
3 conn `l2tp-psk*` đặt mặc định để tránh đụng nhau (`auto=ignore` cho rekey & no-nat). Cách
chọn:
```bash
# test L2TP cơ bản / P1.7 / P1.2  -> chỉ l2tp-psk (mặc định auto=add)
# test P1.3 rekey:
sudo docker exec -it lab-strongswan ipsec stop          # hoặc sửa ipsec.conf: l2tp-psk auto=ignore
sudo docker exec -it lab-strongswan sh -c 'sed -i "s/auto=ignore/auto=add/" /etc/ipsec.conf'  # bật l2tp-psk-rekey
sudo docker compose restart strongswan
# test P0.8c no-NAT: tương tự, bật l2tp-psk-nonat, đảm bảo client KHÔNG sau NAT (host-only).
```
> Đơn giản hơn: tạm sửa `ipsec.conf` đổi `also=%default` của **một** conn rồi `restart`.
> (Tránh để cả 3 conn cùng `auto=add` — proposal trùng dễ gây nhầm conn.)

---

## 7. DEBUG + CAVEAT đã biết

### 7.1 P0.8c — Windows hay "nuốt" proto-50 inbound
Windows có IPsec/IKEEXT service + Windows Filtering Platform có thể **chặn/ăn ESP proto-50
inbound** trước khi tới raw socket của client .NET ⇒ P0.8c trên Windows là **best-effort**.
**Linux là môi trường tham chiếu.** Nếu cần validate P0.8c sạch:
- Chạy client .NET **trong một container/VM Linux** có `CAP_NET_RAW` (vd thêm một service
  vào compose chạy `mcr.microsoft.com/dotnet/sdk` + mount source, `cap_add: [NET_RAW]`),
  hoặc một VM Linux thứ hai làm client.
- Trên Windows, thử **tắt** dịch vụ "IKE and AuthIP IPsec Keying Modules" (IKEEXT) +
  thêm rule firewall cho phép proto-50, nhưng vẫn có thể không sạch.

### 7.2 ULA vs IPv6 global thật
Lab dùng prefix **ULA** `fd00:dead:beef::/64`. ULA có **scope global** (đủ để chứng minh
P1.1: client tạo địa chỉ global-scope qua SLAAC/RA và định tuyến nội bộ lab), nhưng **không
ra internet thật**. Muốn `http-request` qua IPv6 ra internet:
- **NÂNG CAO IPv6 thật:** cần prefix IPv6 **global thật** (ISP cấp, hoặc tunnel broker
  he.net/Hurricane Electric), gán vào `[ipv6-pool]` + bật **forwarding** + **NAT66** hoặc
  định tuyến prefix về VM. Khi đó client lấy địa chỉ global thật ra internet được. Nằm
  ngoài phạm vi lab cơ bản — ghi chú để mở rộng sau.

### 7.3 Cert SSTP self-signed
Đã nêu §5: client phải chấp nhận cert bất kỳ. Cert sinh bởi `accel-ppp/entrypoint.sh`
(`CN=lab-accel-ppp`, SAN IP 127.0.0.1). Nếu muốn pin host theo IP, thêm IP VM vào SAN:
sửa `entrypoint.sh` thêm `IP:<VM_IP>` vào `-addext subjectAltName=...` rồi `down -v` + `up`.

### 7.4 Lệnh chẩn đoán nhanh
```bash
# Log tổng
sudo docker compose logs --tail=200 accel-ppp
sudo docker compose logs --tail=200 strongswan

# Trong container
sudo docker exec -it lab-accel-ppp  accel-cmd show sessions
sudo docker exec -it lab-accel-ppp  ip -6 addr show
sudo docker exec -it lab-strongswan ipsec statusall
sudo docker exec -it lab-strongswan ipsec status

# Bắt gói trên VM (host) — phân biệt ESP proto-50 vs UDP/4500 (P0.8c)
sudo tcpdump -ni any proto 50                 # ESP native
sudo tcpdump -ni any udp port 4500            # ESP-in-UDP (float NAT-T)
sudo tcpdump -ni any udp port 500             # IKE
sudo tcpdump -ni any tcp port 443             # SSTP
sudo tcpdump -ni any 'ip6'                    # outer IPv6 (P1.2)

# journald nếu chạy ngoài docker
journalctl -u docker -f
```

### 7.5 ⚠️ SỰ CỐ ĐÃ GẶP THẬT: bring-up làm SẬP MẠNG VM (mất cả SSH lẫn ping)

**Triệu chứng (đã xảy ra):** chạy `docker compose up -d --build` với **CẢ HAI** service ở
`network_mode: host` (strongSwan thêm `privileged: true`) → ngay sau khi 2 container start,
**VM mất hoàn toàn kết nối mạng**: SSH chết, `ping <VM_IP>` 100% loss. Không vào lại được bằng SSH.

**Nguyên nhân:** container `network_mode: host` **dùng chung network namespace của VM**. Service
chạy đặc quyền trong đó (strongSwan đụng **XFRM/netlink/policy**, hoặc forwarding/rp_filter) **phá
luôn stack mạng của chính VM**. (Triệu chứng "đen" toàn bộ traffic rất khớp với **policy XFRM bẫy
gói chờ SA → drop hết**.) Ngoài ra Docker **từ chối `sysctls` trong `network_mode: host`**
("not allowed in host network namespace") nên container còn không start được nếu để khối `sysctls`.

**Khôi phục — KHÔNG cần reboot** (làm trong **console VMware**, vì SSH đã chết; các lệnh đều local):
```bash
cd ~/lab && docker compose down            # gỡ container (thủ phạm) — ~90% là đủ, mạng về ngay
# nếu vẫn chưa về (do strongSwan để lại policy IPsec):
sudo ip xfrm policy flush && sudo ip xfrm state flush
# nếu route/interface bị mất:
ip -br a ; ip route ; sudo netplan apply    # (hoặc: sudo systemctl restart systemd-networkd)
ping -c2 8.8.8.8                            # ok là xong
```
`docker compose down` xoá hẳn container nên cũng triệt `restart: unless-stopped` tự bật lại.

**PHÒNG TRÁNH (đã áp dụng cho service accel-ppp):**
- **SSTP KHÔNG cần host-networking.** SSTP là **TLS/TCP 443 thuần**; PPP + IPv6 Router Advertisement
  chạy **bên trong** tunnel (interface ppp nội bộ netns container). → Chạy accel-ppp **bridged +
  `ports: "443:443"`** (giữ `/dev/ppp` + `cap_add: NET_ADMIN`, **bỏ** `network_mode: host` và
  `privileged`). `NET_ADMIN` lúc này chỉ tác động netns container, **không đụng `ens33` của VM**.
  Đủ validate **P1.1** (SLAAC-over-PPP) mà KHÔNG có rủi ro sập mạng. (compose hiện đã để vậy.)
- **Chỉ strongSwan** (L2TP/IPsec, ESP proto-50, GRE) mới **thật sự cần** `network_mode: host` +
  `privileged` — đây là phần rủi ro. **Bật RIÊNG, sau cùng**, từng bước, và **kiểm SSH còn sống
  sau mỗi bước**: `docker compose up -d strongswan` rồi ngay lập tức từ một phiên khác
  `ssh <VM> 'echo alive'`. Nếu mất mạng → `docker compose down` từ console như trên.
- **Quy tắc vàng:** bao giờ cũng **bật từng service một**, verify SSH sau mỗi service; đừng `up` cả
  cụm host-net một lượt.

### 7.6 Ghi chú as-built khác đã phát hiện khi chạy thật (đã sửa trong file lab)
- `accel-ppp` **KHÔNG có gói apt** trên Ubuntu 24.04 → Dockerfile **build từ source** (cần
  `libssl-dev` + `libpcre2-dev`; binary `/usr/sbin/accel-pppd`, module `/usr/lib64/accel-ppp`).
- `accel-pppd -d` là **daemon mode** (fork nền) → container thoát ngay; phải chạy **foreground**
  (bỏ `-d`).
- accel-ppp **KHÔNG có section `[ipv6-nd]`** — load module `ipv6_nd` là tự gửi RA; `ipv6-intf-id`
  dạng `0:0:0:1` (không phải `random`); IPv6 pool gán per-listener bằng `ipv6-pool=<tên>`.
- Thiếu `[client-ip-range]` ⇒ accel-ppp **từ chối mọi kết nối** ("incoming ... will be rejected");
  thêm `[client-ip-range]\ndisable` cho lab.

---

## 8. Điểm KHÔNG CHẮC — cần tinh chỉnh live

> Đây là BẢN NHÁP. Các điểm dưới gần như chắc phải sửa khi chạy thật. Đã đánh dấu `# CHECK:`
> tại chỗ trong file config.

| # | File | Điểm nghi ngờ |
|---|---|---|
| 1 | `accel-ppp/Dockerfile` | Gói `accel-ppp` của apt Ubuntu 24.04 có thể **thiếu module sstp/ipv6** hoặc tên khác ⇒ phải build từ source (ghi chú "NÂNG CAO" cuối Dockerfile). Tên binary `accel-pppd` vs `accel-ppp`. |
| 2 | `accel-ppp/accel-ppp.conf` | **Tên module/section IPv6 ND**: `ipv6_nd` / `ipv6pool` / `ipv6_dhcp` và section `[ipv6-nd]`/`[ipv6-pool]`/`[ipv6-dhcp]` — cú pháp đổi theo phiên bản. **Cú pháp prefix** `fd00:dead:beef::/48,64` (prefix,client-len) có thể khác. Option `ipv6=allow`, `ipv6-peer-intf-id`. Cổng CLI `tcp=127.0.0.1:2000`. |
| 3 | `accel-ppp/accel-ppp.conf` | `[l2tp] secret=vpn`: client TqkLibrary có gửi L2TP tunnel secret không? Nếu không, **bỏ** dòng `secret`. |
| 4 | `accel-ppp/entrypoint.sh` | OpenSSL cũ không có `-addext` (đã có fallback). accel-ppp có thể cần **key và cert tách file** thay vì gộp PEM (`ssl-pemfile` vs `ssl-keyfile`+`ssl-certfile`). |
| 5 | `strongswan/Dockerfile` | Bản strongSwan của 24.04 có thể **bỏ starter/`ipsec.conf`**, chỉ còn `swanctl`/vici ⇒ phải chuyển sang `swanctl.conf` (ghi chú cuối Dockerfile + entrypoint). |
| 6 | `strongswan/ipsec.conf` | **Transform `ike=`/`esp=`** phải khớp đề xuất của `IkeV1Client`. Nếu handshake fail → soi log charon xem transform nào bị từ chối rồi chỉnh. `leftprotoport=17/1701` cho L2TP transport mode. |
| 7 | `strongswan/ipsec.conf` | Phối hợp với accel-ppp: ai giữ 1701? Ở đây **accel-ppp** nghe 1701 (LNS), strongSwan chỉ bọc ESP. Cần chắc strongSwan **không** cũng cố mở xl2tpd/1701 (lab này KHÔNG cài xl2tpd — dùng accel-ppp làm L2TP). |
| 8 | `strongswan/entrypoint.sh` | Lệnh foreground `ipsec start --nofork` vs `/usr/lib/ipsec/starter --nofork` vs `charon`. `privileged: true` để cài XFRM SA — thu hẹp cap sau khi chạy được. |
| 9 | `docker-compose.yml` | `network_mode: host` + 2 service không trùng cổng. `/dev/ppp` phải tồn tại trên host (`modprobe ppp_generic`). `sysctls` trong host-net mode đôi khi bị bỏ qua ⇒ đặt sysctl ở HOST (§3.3). |
| 10 | Client (ngoài lab) | Demo **đã có** flag `--ipv6` cho P1.1 (SSTP/L2TP). Còn **HonestFirst** + **native-ESP factory** cho P0.8c thì chưa wire ⇒ cần thêm flag tạm hoặc test integration gọi driver trực tiếp. |

---

## 9. Cấu trúc thư mục lab

```
lab/
├─ docker-compose.yml          # 2 service host-net: accel-ppp + strongswan
├─ README-vi.md                # file này (runbook)
├─ accel-ppp/
│  ├─ Dockerfile               # ubuntu:24.04 + accel-ppp
│  ├─ accel-ppp.conf           # SSTP/L2TP/PPTP + IPv6 pool + RA/SLAAC  (P1.1/P1.7)
│  ├─ chap-secrets             # user vpn / pass vpn
│  └─ entrypoint.sh            # sinh cert SSTP self-signed + chạy daemon
└─ strongswan/
   ├─ Dockerfile               # ubuntu:24.04 + strongswan
   ├─ ipsec.conf               # 3 conn: l2tp-psk / -rekey(P1.3) / -nonat(P0.8c)
   ├─ ipsec.secrets            # PSK "vpn"
   ├─ strongswan.conf          # charon (không ép NAT-T global)
   └─ entrypoint.sh            # chạy charon foreground
```

---

## 10. Lưu ý cuối

- **BẢN NHÁP**: lần chạy đầu phải tinh chỉnh (§8). Đừng coi lab này là "đã test chạy được".
- Lab chứng minh **đường đi** (SLAAC-over-PPP tạo global IPv6, ESP proto-50 no-NAT, rekey
  Phase1, multi-session); để ra internet IPv6 thật cần prefix global thật (§7.2).
- Mở rộng tương lai (ngoài P1/P0.8): thêm OpenVPN / WireGuard / ocserv / SoftEther vào compose
  cho V.x (Q.1 đầy đủ) — giữ nguyên pattern host-net + cap.
```
