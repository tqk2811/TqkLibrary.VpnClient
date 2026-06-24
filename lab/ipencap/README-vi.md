# lab/ipencap — validate LIVE driver V.8 IpEncap (GRE-47 / IPIP-4 / SIT-41, no-NAT)

Lab RIÊNG để validate **V.8** của driver IP-encap repo TqkLibrary: encapsulation **TRẦN
connectionless** (không control plane / handshake / auth) chở gói IP thẳng trên số hiệu
giao thức IP riêng qua **raw socket**:

- **GRE** proto-47 (RFC 2784/2890 — `GreTunnelChannel`, GRE v0, no key/seq/checksum)
- **IPIP** proto-4 (RFC 2003 — `RawIpPassthroughChannel`, IPv4-in-IPv4 header-less)
- **SIT/6in4** proto-41 (RFC 4213 — `RawIpPassthroughChannel`, IPv6-in-IPv4 header-less)

Peer = **Linux `ip tunnel` thuần** (`ip link add gre1/ipip1/sit1 type gre/ipip/sit`),
không daemon. Client = binary demo `.NET` self-contained publish (linux-x64), chạy trong
container cùng bridge.

**Topology AN TOÀN (nhái [`../l2tp-nonat`](../l2tp-nonat/README-vi.md) + [`../pptp`](../pptp/README-vi.md)):**
2 container trên cùng custom bridge `labnet` **subnet TĨNH** (`172.30.0.0/24` để peer biết
trước IP client mà đặt `remote` cho ip-tunnel), KHÔNG `network_mode: host`, KHÔNG privileged —
chỉ `NET_ADMIN` (peer) + `NET_RAW` (client) trong netns container. Intra-bridge KHÔNG NAT ⇒
gói proto-47/4/41 đi L2 thẳng (giống native-ESP proto-50 P0.8c). Peer dùng `NET_ADMIN` tạo
ip-tunnel ⇒ kernel TỰ autoload module `ip_gre`/`ipip`/`sit` (không cần `modprobe`/sudo trên host).

---

## ⚑ Kết quả validate LIVE (2026-06-24) — CẢ 3 KIỂU 2 CHIỀU, 0 BUG

Encapsulation trần connectionless là **sạch nhất** (không handshake/auth) — codec IpEncap
đúng **byte-for-byte với Linux kernel ip-tunnel ngay lần đầu**, KHÔNG cần sửa code driver/protocol.

| Kiểu | Proto | Bằng chứng (tcpdump trên peer + `ip -s link` + client log) |
|------|-------|-----------------------------------------------------------|
| **GRE** | 47 | pcap `GREv0, Flags [none]` (no key/seq/checksum — khớp `ip link type gre` no-key); inner ICMP echo request→reply + UDP DNS query→response 2 chiều; gateway `10.80.0.1` RTT 1ms; `gre1` link RX/TX 3/3 |
| **IPIP** | 4 | pcap `proto IPIP (4)` header-less, inner-IP verbatim; ICMP + UDP DNS 2 chiều; gateway `10.81.0.1` RTT 1ms; `ipip1` link RX/TX 3/3 |
| **SIT** | 41 | pcap `proto IPv6 (41)`, inner IPv6 verbatim (`fd00::2 ↔ fd00::1`); UDP DNS-over-UDP 2 chiều; stack dual-stack; `sit1` link RX/TX 2/2 |

**Connectionless ⇒ IP tunnel TĨNH:** driver không có IPCP/DHCP nên demo gán địa chỉ tunnel
qua query string của URI: `?addr=<v4>/<prefix>&peer=<v4>` (GRE/IPIP) hoặc
`?addr6=<v6>/<prefix>&peer6=<v6>` (SIT). `peer` là gateway trong tunnel — đích ICMP/UDP probe.

---

## Cách chạy (runbook)

```bash
# Trên Windows host: publish self-contained + scp sang VM (xem fvq-overnight-progress §V.8)
dotnet publish demo/Vpn2ProxyDemo -c Release -r linux-x64 --self-contained -o <out>
# tar <out> → scp vpnlab:/tmp/ → giải nén vào ./client-bin

cd ~/lab/ipencap && docker compose up -d   # peer dựng gre1/ipip1/sit1 + dnsmasq

# GRE proto-47:
docker exec lab-ipencap-client /opt/client/Vpn2ProxyDemo dns \
  --vpn 'gre://peer@ipencap-peer?addr=10.80.0.2/24&peer=10.80.0.1' --resolve example.com
# IPIP proto-4:
docker exec lab-ipencap-client /opt/client/Vpn2ProxyDemo dns \
  --vpn 'ipip://peer@ipencap-peer?addr=10.81.0.2/24&peer=10.81.0.1'
# SIT proto-41 (IPv6-in-IPv4):
docker exec lab-ipencap-client /opt/client/Vpn2ProxyDemo dns \
  --vpn 'sit://peer@ipencap-peer?addr6=fd00::2/64&peer6=fd00::1'

# Quan sát phía peer:
docker exec -d lab-ipencap-peer tcpdump -ni eth0 -v proto 47 -c 6 -w /tmp/gre.pcap  # đổi proto 47|4|41
docker exec lab-ipencap-peer ip -s link show gre1                                   # gre1|ipip1|sit1: RX/TX > 0

docker compose down -v   # dọn
```

Demo cần `cap_add: NET_RAW` (đã đặt trong compose) để mở raw socket proto-47/4/41.

⚠️ **GRE/IPIP/SIT TRẦN không mã hóa** — chỉ dùng trên đường tin cậy hoặc dưới IPsec ESP.
