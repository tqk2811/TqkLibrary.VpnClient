# 09 — Userspace TCP/IP stack & link abstraction

> Không có stack userspace .NET sẵn → tự viết. Thiết kế boundary theo tiền lệ gVisor netstack / smoltcp / lwIP.

## Tiền lệ: boundary = 1 link object có thuộc tính Medium

| Stack | Abstraction | L3 (IP) | L2 (Ethernet) |
|---|---|---|---|
| **gVisor** | `stack.LinkEndpoint` | `link/channel.Endpoint` (MaxHeaderLength=0, AddHeader no-op) | `link/ethernet` wrapper + `ARPHardwareType` |
| **smoltcp** | `phy::Device` + `Medium` | `Medium::Ip` ("no MAC, no ARP/NDISC"; vd PPP, L3 VPN) | `Medium::Ethernet` ("must do ARP/NDISC"; vd L2 VPN) |
| **lwIP** | `netif` | không `NETIF_FLAG_ETHARP` | `NETIF_FLAG_ETHARP` |

→ Ta mô phỏng: `ILinkChannel` base + `Medium` property; ARP/neighbor-discovery gate theo Medium (= gVisor `CapabilityResolutionRequired`).

## Interface (Abstractions)

```
ILinkChannel               : Mtu, MaxHeaderLength, Medium{Ip|Ethernet},
                             RequiresLinkAddressResolution
  ├─ IPacketChannel        : ValueTask WriteIpPacketAsync(ROM<byte>); event InboundIpPacket   (L3)
  └─ IEthernetChannel       : ValueTask WriteFrameAsync(EthernetFrame); LinkAddress(MAC)        (L2)
```

- **Quy tắc vàng:** `ITcpipStack` (TCP/UDP/ICMP) **chỉ** bind `IPacketChannel`, không bao giờ thấy Ethernet.
- L3 driver dùng `PassthroughPacketChannel` (identity, MaxHeaderLength=0).

## EthernetAdapter — phân rã, KHÔNG monolith

```
EthernetAdapter (: IPacketChannel-provider)
 ├─ EthernetSwitch          : FDB MAC-learning; unicast theo dest-MAC; flood broadcast/unknown
 └─ VirtualHost[]           : mỗi cái = {MAC, INeighborResolver(ARP), IAddressConfigurator(DHCP), IPacketChannel}
 (sidecar tuỳ chọn: INatTranslator, IDnsResolver)
```

- "Nhiều máy trên 1 kết nối L2" rơi ra tự nhiên: mỗi VirtualHost 1 MAC + 1 DHCP lease + 1 IpStack.
- NAT/DNS KHÔNG mặc định nhồi vào — sidecar cắm thêm (mô hình tsnet: stack tự originate connection từ IP đã lease).

## Userspace TCP/IP stack — phạm vi

- **IPv4:** parse/checksum/reassembly/demux (TCP/UDP/ICMP). IPv6 sau.
- **UDP:** demux theo port, datagram in/out.
- **ICMP:** echo (ping) + error.
- **TCP state machine:** CLOSED→SYN_SENT→ESTABLISHED→...→TIME_WAIT; RTO (RFC 6298 đơn giản), sliding window, MSS/MTU. **Bản tối giản:** no SACK, no window-scaling, cwnd nhỏ cố định — đủ client outbound. Tham chiếu cấu trúc smoltcp/lwIP.

## Hiệu năng
- `System.Threading.Channels` / `PipeReader`/`PipeWriter` cho mỗi channel, backpressure rõ; **1 read-loop / VirtualHost**.
- `ArrayPool`/`IMemoryOwner`, span-based parsing → không alloc mỗi gói.
- Surface `Mtu`/`MaxHeaderLength` trên channel; L2 trừ 14 byte Ethernet header → stack trên EthernetAdapter quảng cáo MTU giảm + clamp MSS (L2 VPN hay vỡ PMTUD).

## Test
- Round-trip gói IPv4/TCP/UDP dựng sẵn (checksum biết trước).
- Nối 2 instance IpStack qua loopback `IPacketChannel` → 1 bên `ConnectTcp` bên kia in-process (kiểm 3-way/4-way).
- Channel cố tình drop/đảo gói → kiểm retransmit. Fuzz parser.

## Nguồn
- gVisor stack: https://pkg.go.dev/gvisor.dev/gvisor/pkg/tcpip/stack
- gVisor link/channel: https://pkg.go.dev/gvisor.dev/gvisor/pkg/tcpip/link/channel
- smoltcp Medium: https://docs.rs/smoltcp/latest/smoltcp/phy/enum.Medium.html
- lwIP netif: https://www.nongnu.org/lwip/2_1_x/group__netif.html
- gvisor-tap-vsock: https://github.com/containers/gvisor-tap-vsock
- RFC 6298 (RTO): https://datatracker.ietf.org/doc/html/rfc6298
