# 03 — Multi-host: L2 vs L3 (đã verify đối kháng với RFC/spec)

> Câu hỏi gốc: "Một kết nối tới VPN server có tạo được nhiều máy trong LAN không?"

## Kết luận ngắn

- **L3/PPP (L2TP/IPsec, MS-SSTP)** = point-to-point IP, **1 IP/session**, KHÔNG ARP/DHCP/broadcast. Không phải "máy trong LAN".
- **L2 (Ethernet — SoftEther, OpenVPN-tap, L2TPv3-ETH)** = LAN ảo thật: nhiều `VirtualHost` (MAC + IP riêng) trên 1 kết nối. **Đây mới là "nhiều máy trong LAN" với DHCP/ARP/NAT.**

## L3/PPP chi tiết

Cả L2TP/IPsec (L2TPv2) và MS-SSTP **mang PPP** → client là **host L3 point-to-point**, KHÔNG có:
- Ethernet framing, MAC, ARP, broadcast/multicast subnet, DHCP-on-wire.

| Khía cạnh | Cơ chế |
|---|---|
| Cấp IP | **IPCP** (RFC 1332): client gửi IP-Address option type 3 = `0.0.0.0` → server trả IP trong **Configure-Nak** |
| DNS/WINS | **RFC 1877**: option 129/131 = Primary/Secondary DNS; 130/132 = Primary/Secondary NBNS(WINS). Client gửi 0.0.0.0 → server NAK trả về |
| Gateway | KHÔNG có option gateway trong IPCP → gateway = **ngầm định PPP peer** |
| NAT | làm ở **server** (LNS/RAS). Client gửi từ đúng IP được cấp |
| Anti-spoof | server thường bật **RPF/uRPF** → **drop** gói nguồn ≠ IP được cấp. → bind userspace socket vào đúng IP đó |

### SSTP — strictly 1:1 (MS-SSTP spec)
- 1 PPP session / 1 HTTPS connection. Header SSTP **4 byte** không có session/tunnel/call ID.
- Gói SSTP tối đa **4095 byte** (12-bit Length) → PPP payload **≤ 4091 byte** → ảnh hưởng MRU/MTU.
- Không có sub-channel/multiplexing. **N IP = N kết nối HTTPS** riêng.
- (SoftEther "1–32 parallel TCP" là tính năng riêng của SoftEther, KHÔNG phải MS-SSTP.)

### L2TP/IPsec — protocol cho phép nhiều session, server thường không
- RFC 2661: 1 **Tunnel** (Tunnel ID) mang **nhiều Session** (Session ID); mỗi session = **PPP độc lập** = IPCP riêng = **IP riêng**.
- Thêm session qua **ICRQ/ICRP/ICCN** trên control connection đã mở → **dùng lại cùng IKE/IPsec SA**, KHÔNG phải đàm phán IKE lại.
- NHƯNG: multi-session-per-tunnel là kiến trúc **carrier (LAC↔LNS)**. Client remote-access (RRAS/xl2tpd/SoftEther) thường chỉ **1 session = 1 IP**.
- Ràng buộc thực tế mạnh hơn: **1 kết nối L2TP/IPsec / 1 source IP** (do IPsec transport-mode + NAT-T).
- → **Thiết kế:** mặc định 1 kết nối/1 IP; hỗ trợ multi-session là **best-effort, test theo server**.

## L2 chi tiết — bộ kích hoạt multi-host

L2 VPN giao **khung Ethernet** → cần một sublayer userspace (KHÔNG cần TAP) mô phỏng dịch vụ LAN:

```
EthernetAdapter
 ├─ EthernetSwitch           : FDB MAC-learning; unicast theo dest-MAC; flood broadcast/unknown-unicast
 └─ N × VirtualHost
        ├─ MAC riêng
        ├─ INeighborResolver  (ARP responder/resolver)
        ├─ IAddressConfigurator (DHCP client userspace → lấy IP/gateway/DNS như host LAN thật)
        └─ IPacketChannel → 1 instance IpStack riêng
 (+ INatTranslator, IDnsResolver : sidecar tuỳ chọn)
```

- Mỗi `VirtualHost` = một "máy" trên segment Ethernet ảo: MAC riêng, IP riêng (DHCP), stack riêng.
- Demux: switch tra dest-MAC trong FDB → giao đúng VirtualHost; broadcast/unknown → flood tất cả (ARP/DHCP DISCOVER chạy được).
- Tiền lệ production: **SoftEther SecureNAT** (virtual DHCP + virtual NAT, userspace), **gvisor-tap-vsock** (userspace DHCP/DNS/NAT/ARP, không TUN/TAP).
- Phụ thuộc policy server: SoftEther có "Maximum Number of MAC Addresses" (default unlimited, 1–65535) + "Deny Bridge/Deny Routing"; OpenVPN-tap cần server chạy bridge. → multi-MAC cần server cho phép.

## Nguồn
- RFC 2661 (L2TPv2): https://www.rfc-editor.org/rfc/rfc2661.txt
- RFC 1332 (IPCP): https://www.rfc-editor.org/rfc/rfc1332.html
- RFC 1877 (IPCP DNS/NBNS): https://datatracker.ietf.org/doc/html/rfc1877
- MS-SSTP: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/70adc1df-c4fe-4b02-8872-f1d8b9ad806a
- SoftEther L2/SecureNAT: https://www.softether.org/4-docs/1-manual/3/3.7
- gvisor-tap-vsock: https://github.com/containers/gvisor-tap-vsock
