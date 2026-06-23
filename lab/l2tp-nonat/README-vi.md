# lab/l2tp-nonat — validate LIVE P0.8c (native ESP proto-50, no-NAT)

Lab RIÊNG để validate **P0.8c** của driver L2TP/IPsec repo TqkLibrary: client lấy
**ESP proto-50 native** (KHÔNG float UDP/4500) khi **không có NAT** giữa client và server,
dưới NAT-T mode **HonestFirst**.

Server = **strongSwan** (IKEv1 PSK + ESP transport, `forceencaps=no`) + **xl2tpd** + **pppd CHUẨN**
(KHÔNG accel-ppp — accel-ppp hỏng FSM IPCP, xem [`../README-vi.md`](../README-vi.md) §7.6).
Client = binary demo `.NET` self-contained publish, chạy trong container cùng bridge.

---

## ⚑ Kết quả validate LIVE — FULL END-TO-END (2026-06-23)

**✅ Tunnel LÊN HẲN — đã chạy thật lab này:** client `--native-esp` (HonestFirst) →
NAT-D detection no-NAT **chính xác byte-perfect** → mở **raw socket proto-50**, gửi/nhận **ESP native proto-50**
(tcpdump: `proto 50 > 0`, `udp port 4500 = 0`), **IKE toàn bộ trên UDP/500 không float** → strongSwan cài
**SA native ESP** (proto-50, **KHÔNG `encap`/espinudp**) → giải mã → L2TP control → **pppd cấp IP `10.31.0.10`**
(`ppp0: 10.31.0.1 peer 10.31.0.10`) → **ICMP qua tunnel RTT 3ms**. Client in `"tunnel up. assigned IP = 10.31.0.10"`
+ `[✓] IPv4 routing`.

- Quá trình này **phát hiện + sửa 3 bug client + 1 lab-config** (KHÔNG cần redesign `Decide`):
  1. **`.NET raw socket EPROTONOSUPPORT`** — `new Socket(.., Raw, (ProtocolType)50)` fail trên Linux dù kernel cho
     (libc `socket()` chạy OK); fix [`NativeRawSocket`](../../src/TqkLibrary.VpnClient.Transport.RawIp/NativeRawSocket.cs) mở fd qua libc.
  2. **honest-path identity `0.0.0.0`** — Quick Mode ID_ci = `IPAddress.Any` làm strongSwan tưởng NAT; fix dùng `localIp` thật.
  3. **Quick Mode encapsulation-mode order** — [`IkeV1Proposals.Phase2`](../../src/TqkLibrary.VpnClient.Ipsec/Ike/V1/IkeV1Proposals.cs)
     trước đây luôn xếp `UDP-Encapsulated-Transport`(4) TRƯỚC `Transport`(2) ⇒ responder strongSwan chọn transform đầu = espinudp
     → drop native proto-50 **dù KHÔNG NAT** (NAT-D đã khớp byte-perfect). Fix cờ `preferTransport` /
     [`IkeV1Client.PreferNativeTransport`](../../src/TqkLibrary.VpnClient.Ipsec/Ike/V1/IkeV1Client.cs) — native path đề xuất `Transport` trước
     (forced path GIỮ UDP-encap trước, không đổi đường live VPN Gate). **Đây là root-cause `espinudp` lần đầu**, KHÔNG phải blocker phía server.
  4. **lab `options.xl2tpd` có option `lock`** — pppol2tp không nhận ⇒ pppd exit 2; gỡ ở lab.

**Control-test xác nhận strongSwan ĐÚNG RFC:** một strongSwan **client chuẩn** (no-NAT) nối CÙNG server → cũng nhận
**native ESP** (SA không `encap`, QM không NAT-OA). Tức no-NAT ⇒ native ESP là hành vi đúng của strongSwan; espinudp
trước đây hoàn toàn do **client TA đề xuất UDP-encap-first ở Quick Mode** (bug #3), KHÔNG phải strongSwan quirk và
KHÔNG phải [`L2tpIpsecNatStrategy.Decide`](../../src/TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecNatStrategy.cs) sai —
`Decide` **đúng nguyên trạng, KHÔNG redesign**.

**Đã bake vào lab để charon chạy được (xác nhận live):** [`Dockerfile`](Dockerfile) gỡ plugin `kernel-libipsec`
(đòi `/dev/net/tun` không có → charon ABORT khi load); [`strongswan.conf`](strongswan.conf) tắt `bypass-lan`
(PASS shunt subnet local làm reply server đi **plaintext** thay vì ESP → client không nhận); [`options.xl2tpd`](options.xl2tpd) gỡ `lock`.

---

## 1. Topology — vì sao AN TOÀN (khác lab cũ)

```
   ┌───────────────────────── Docker bridge tùy biến: labnet ─────────────────────────┐
   │                                                                                   │
   │   [dotnet-client]                                   [l2tp-server]                 │
   │   runtime-deps:8.0                                  ubuntu:22.04                  │
   │   cap_add: NET_RAW          IKEv1/500 + ESP proto-50  strongSwan (charon)         │
   │   /opt/client/Vpn2ProxyDemo  ─────────────────────►   + xl2tpd (UDP/1701)         │
   │     --native-esp (P0.8c)    ◄─────────────────────    + pppd CHUẨN (IPCP/IPV6CP)  │
   │                              proto-50 ĐI L2 THẲNG                                  │
   │                              (KHÔNG NAT giữa 2 container cùng bridge)              │
   └───────────────────────────────────────────────────────────────────────────────────┘
                       KHÔNG host-net · KHÔNG privileged-host · KHÔNG publish cổng
```

**Vì sao no-NAT (điều kiện kích hoạt native-ESP):** 2 container ở CÙNG một bridge tùy biến →
gói đi **L2 thẳng** giữa chúng, Docker **KHÔNG NAT** traffic intra-bridge (NAT chỉ áp cho gói
ra NGOÀI host). IKE NAT-Discovery (NAT-D) thấy hash địa chỉ **khớp** → kết luận "không có NAT" →
strongSwan **giữ ESP proto-50** thật (không float UDP/4500). Đó chính là kịch bản **HonestFirst**
của driver.

**Vì sao AN TOÀN (so với lab cũ — [`../README-vi.md`](../README-vi.md) §7.5):**
- **KHÔNG `network_mode: host`** → strongSwan đụng **XFRM/netlink** chỉ trong **netns riêng của
  container**, nếu phá thì chỉ phá netns chính nó, **KHÔNG đụng `ens33`/mạng VM**. (Lab cũ host-net
  từng làm **SẬP cả SSH lẫn ping** của VM.)
- **KHÔNG `privileged` trên host** → chỉ `NET_ADMIN` (server) / `NET_RAW` (client) trong netns con.
- **KHÔNG publish cổng** → test hoàn toàn nội bộ bridge, không lộ ra LAN.

---

## 2. Chuẩn bị VM (một lần)

```bash
# pppd/xl2tpd cần module kernel ppp + thiết bị /dev/ppp trên host VM.
sudo modprobe ppp_generic
echo ppp_generic | sudo tee /etc/modules-load.d/ppp.conf   # persist qua reboot
ls -l /dev/ppp                                             # phải thấy character device
```

> Nếu `/dev/ppp` không có sau modprobe, kiểm `lsmod | grep ppp` và kernel có `CONFIG_PPP`.
> Compose mount `devices: /dev/ppp:/dev/ppp` — host phải có sẵn TRƯỚC khi `up`.

---

## 3. Publish client từ Windows host rồi đưa vào VM

Trên **Windows host** (thư mục repo), publish demo **self-contained linux-x64** (KHÔNG chạy ở đây —
chỉ tạo binary để copy sang VM):

```powershell
# Tên assembly = Vpn2ProxyDemo (đã xác minh: csproj không đặt AssemblyName ⇒ = tên project).
dotnet publish demo/Vpn2ProxyDemo -c Release -r linux-x64 --self-contained true -o lab/l2tp-nonat/client-bin
```

Kết quả: `lab/l2tp-nonat/client-bin/Vpn2ProxyDemo` (binary ELF linux-x64) + các .dll/.so kèm theo.

Copy thư mục `client-bin` sang VM (rsync hoặc scp), đặt đúng tại `lab/l2tp-nonat/client-bin` trong
cây lab trên VM (compose mount `./client-bin:/opt/client:ro`):

```bash
# từ Windows host (ví dụ, đổi <vm> theo host SSH của bạn):
rsync -av lab/l2tp-nonat/client-bin/  <vm>:~/lab/l2tp-nonat/client-bin/
#   hoặc: scp -r lab/l2tp-nonat/client-bin <vm>:~/lab/l2tp-nonat/
# trên VM: đảm bảo binary có quyền chạy
chmod +x ~/lab/l2tp-nonat/client-bin/Vpn2ProxyDemo
```

> ✅ **`--native-esp` ĐÃ wire vào CLI** (validate live). Là option **chung**, áp cho `dns` / `http-request` /
> `proxy-server`; khi bật **và** scheme `l2tp` → demo dựng driver L2TP/IPsec với `RawIpTransportFactory` +
> `L2tpIpsecNatTraversalMode.HonestFirst` (ESP native proto-50). Cần **root / CAP_NET_RAW** — container client đã có
> `cap_add: NET_RAW`. Bật cờ với scheme khác `l2tp` ⇒ demo in cảnh báo + bỏ qua (không crash).

---

## 4. Bring-up

```bash
cd lab/l2tp-nonat
sudo docker compose up -d --build      # build server image + chạy 2 container nền

sudo docker compose ps
sudo docker compose logs -f l2tp-server   # soi charon + xl2tpd
```

> An toàn: cả 2 container ở bridge `labnet` (KHÔNG host-net) ⇒ bring-up **không rủi ro mạng VM**.
> Nếu cần dừng: `sudo docker compose down` (xem §7 Teardown).

---

## 5. Chạy client + quan sát THÀNH CÔNG

Lấy tên container client + chạy demo trong đó (server resolve qua tên service `l2tp-server`):

```bash
# Sau khi đã wire --native-esp vào demo (xem §3 cảnh báo) + publish lại:
sudo docker exec -it lab-l2tp-client \
    /opt/client/Vpn2ProxyDemo dns \
    --vpn 'l2tp://vpn:vpn@l2tp-server?psk=vpn' \
    --native-esp
#   (tên 'l2tp-server' resolve trên bridge labnet → IP container server)
#   Đổi 'dns' thành 'proxy-server' / 'http-request --url ...' cho hành động khác.
```

**Cách quan sát THÀNH CÔNG (chạy song song trong netns server):**

```bash
# 1) ESP proto-50 NATIVE (KHÔNG phải udp/4500) — bằng chứng no-NAT:
sudo docker exec lab-l2tp-server tcpdump -ni any proto 50
#    THẤY: gói ESP. KHÔNG thấy 'udp port 4500' tức KHÔNG float NAT-T → đúng P0.8c.

# 2) IKE giữ UDP/500 (không float sang 4500):
sudo docker exec lab-l2tp-server tcpdump -ni any udp port 500
#    THẤY: IKE Main Mode + Quick Mode trên 500. (Nếu thấy 4500 = đã float = SAI kịch bản.)

# 3) SA KHÔNG có NAT-T/encap:
sudo docker exec lab-l2tp-server ipsec statusall
#    THẤY: ESP SA proto-50, KHÔNG có dòng 'NAT-T'/'encap'/'UDP-encapsulation'.

# 4) Client lên IPCP, lấy IP 10.31.0.x:
sudo docker exec lab-l2tp-server sh -c 'ip -4 addr show; ip route'
#    THẤY: interface ppp0 (gateway 10.31.0.1) + peer 10.31.0.10..20.
#    Hoặc soi log: sudo docker compose logs l2tp-server | grep -i ipcp
```

---

## 6. Điểm cần tinh chỉnh LIVE (`# CHECK:` trong config)

| # | File | Điểm nghi ngờ |
|---|---|---|
| 1 | [`ipsec.conf`](ipsec.conf) | **Transform `ike=`/`esp=`** phải khớp đề xuất của `IkeV1Client`. Handshake fail → soi `ipsec statusall` + charon log xem transform nào bị từ chối, thêm vào (vd 3DES/MD5/MODP1536). |
| 2 | [`xl2tpd.conf`](xl2tpd.conf) | **L2TP tunnel secret**: client TqkLibrary có gửi tunnel secret không? Nếu KHÔNG, để mặc định (không `challenge`); nếu CÓ, thêm `challenge = yes` + secret khớp. |
| 3 | [`entrypoint.sh`](entrypoint.sh) | **Daemon foreground**: `ipsec start` (nền) + `exec xl2tpd -D` (foreground). Nếu bản strongSwan systemd-only, đổi sang `/usr/lib/ipsec/starter --daemon charon`. xl2tpd cần `/dev/ppp` + `/var/run/xl2tpd`. |
| 4 | [`options.xl2tpd`](options.xl2tpd) | **pppd auth**: `require-mschap-v2` — nếu client chỉ làm CHAP thường, đổi `require-chap`. MTU/MRU 1410 có thể cần hạ (1400/1380) nếu phân mảnh. KHÔNG bật mppe. |
| 5 | [`docker-compose.yml`](docker-compose.yml) | **no-NAT thật**: xác nhận tcpdump thấy proto-50 (không 4500). Nếu vẫn float 4500 → kiểm `forceencaps=no` + strongswan.conf không ép nat_traversal; và đảm bảo 2 container đúng cùng `labnet`. |

---

## 7. Teardown

```bash
cd lab/l2tp-nonat
sudo docker compose down               # gỡ 2 container + bridge labnet

# (phòng xa) nếu netns container để lại policy XFRM — KHÔNG ảnh hưởng VM vì netns riêng,
# nhưng container đã gỡ nên cũng sạch theo. Mạng VM KHÔNG bị đụng (khác lab host-net cũ).
sudo docker compose ps                 # xác nhận đã xuống
```

---

## 8. Cấu trúc thư mục

```
lab/l2tp-nonat/
├─ Dockerfile          # ubuntu:22.04 + strongSwan starter + xl2tpd + ppp + tcpdump
├─ ipsec.conf          # IKEv1 PSK, type=transport, forceencaps=no → ESP proto-50 (P0.8c)
├─ ipsec.secrets       # PSK "vpn"
├─ strongswan.conf     # charon, KHÔNG ép NAT-T global (để forceencaps quyết định)
├─ xl2tpd.conf         # LNS: ip range 10.31.0.10-20, local 10.31.0.1, require chap
├─ options.xl2tpd      # pppd: require-mschap-v2, ms-dns, noccp, proxyarp, mtu/mru 1410
├─ chap-secrets        # user vpn / pass vpn / mọi IP
├─ entrypoint.sh       # charon nền + xl2tpd -D foreground
├─ docker-compose.yml  # 2 service trên bridge labnet (server + dotnet-client)
└─ README-vi.md        # file này (runbook)
```

> client-bin/ (binary publish) KHÔNG commit — tạo theo §3 trên từng máy.
