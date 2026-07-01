# TqkLibrary.VpnClient.Drivers.Tinc

Driver **tinc 1.1 (SPTPS)** — ráp các khối protocol thuần ở [`Tinc`](../TqkLibrary.VpnClient.Tinc) (V.7.2 phase a: SPTPS handshake KEX/SIG/derive + record layer TCP/UDP + meta request codec + host-config) thành một tunnel **L3 (router mode)** chạy thật sau facade. tinc cần **CẢ HAI** transport: một **TCP meta-connection** (port 655 — ID, SPTPS handshake, ACK, ADD_SUBNET/ADD_EDGE, và trao đổi khóa data-plane REQ_KEY/ANS_KEY) và một **UDP data plane** (cùng endpoint — SPTPS data datagram, 1 datagram = 1 record). Sau handshake meta, driver thiết lập một **SPTPS session RIÊNG cho data plane** (trao đổi KEX/SIG qua meta REQ_KEY/ANS_KEY, label `"tinc UDP key expansion"`) rồi chở **gói IP trần** (router mode, type 0) qua UDP datagram sau [`SwappablePacketChannel`](../TqkLibrary.VpnClient.Abstractions/Channels/SwappablePacketChannel.cs) ổn định. Config tĩnh [`TincConfig`](Config/TincConfig.cs) (Ed25519 seed của ta + host file của peer: Ed25519PublicKey/Address/Subnet, overlay IP/CIDR, MTU) → `TunnelConfig` **tĩnh** (subnet khai báo sẵn trong host file, **không IPCP/DHCP**). Point-to-point client ↔ 1 node tinc (auto-mesh đa-node là STRETCH chưa làm).

## Vị trí kiến trúc

`DRIVER`-layer, hiện thực [`IVpnProtocolDriver`](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs). Lắp ráp các khối protocol thuần từ [`Tinc`](../TqkLibrary.VpnClient.Tinc) thành 1 tunnel sống (mirror cấu trúc [`Drivers.Nebula`](../TqkLibrary.VpnClient.Drivers.Nebula), thêm meta-connection TCP):

- **Transport (kép)**: seam [`ITincTransportFactory`](Transport/ITincTransportFactory.cs) trả về cặp (TCP meta + UDP data) — production [`TincSocketTransportFactory`](Transport/TincSocketTransportFactory.cs) (tái dùng [`TcpByteStream`](../TqkLibrary.VpnClient.Transport.Tcp/TcpByteStream.cs) F.1 cho meta + `UdpClient` connected cho data), test inject loopback.
- **Meta-connection** [`TincMetaConnection`](Meta/TincMetaConnection.cs): ID cleartext → SPTPS handshake (reuse [`SptpsHandshake`](../TqkLibrary.VpnClient.Tinc/Sptps/SptpsHandshake.cs) + [`SptpsRecordLayer`](../TqkLibrary.VpnClient.Tinc/Sptps/SptpsRecordLayer.cs) — KHÔNG gửi/chờ empty-ACK record, sau ConsumeSig là keyed) → mỗi meta request = 1 application record type 0; xử lý TCP data fallback `SPTPS_PACKET(21) <len>` + `<len>` raw bytes.
- **Data-plane SPTPS (session riêng)**: initiator gửi KEX qua `REQ_KEY` rồi SIG qua `ANS_KEY` (sau khi consume server KEX); server trả KEX+SIG qua ANS_KEY → keyed → bind data channel. Label `"tinc UDP key expansion <me> <peer>"`+NUL.
- **Data plane** [`TincDataTransport`](DataChannel/TincDataTransport.cs): relay header `DSTID(nullid 6)‖SRCID(node_id 6)‖`[`SptpsDatagramRecordLayer`](../TqkLibrary.VpnClient.Tinc/Sptps/SptpsDatagramRecordLayer.cs) (`seqno(4)‖enc‖tag`). node_id = `SHA512(node_name)[:6]` ([`TincNodeId`](DataChannel/TincNodeId.cs)). Bind vào [`TincChannel`](DataChannel/TincChannel.cs) → `IPacketChannel` L3 (bare IP, `MaxHeaderLength`=0); xử lý **PKT_PROBE** (type 4) trả type-2 probe reply để tincd xác nhận UDP 2 chiều.
- **Lifecycle**: meta read loop nền (ACK/ADD_SUBNET/ADD_EDGE/REQ_KEY/ANS_KEY/Ping→Pong) + UDP receive loop + supervisor/auto-reconnect (F.6).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | `IVpnProtocolDriver`/`IVpnConnection`/`IVpnSession`, `IPacketChannel`, `SwappablePacketChannel`, `IByteStreamTransport`/`IDatagramTransport`, exceptions, `IHostResolver`, **`Diagnostics`** (`VpnDropReason`/`VpnLogExtensions`/`LogProtocolStep` — Q.2) |
| Dùng | [Drivers.Core](../TqkLibrary.VpnClient.Drivers.Core) | **`ReconnectingVpnConnection`** (base supervisor F.6) + **`VpnReconnectOptions`** (`TincReconnectOptions` kế thừa) + **`VpnConnectionState`** (enum state dùng chung) |
| Dùng | [Tinc](../TqkLibrary.VpnClient.Tinc) | `SptpsHandshake` (KEX/SIG/derive + `BuildMetaLabel`/`BuildUdpLabel`), `SptpsRecordLayer` (meta TCP), `SptpsDatagramRecordLayer` (data UDP + handshake framing), `TincMetaRequest`/`TincRequestType` (meta line codec), `TincHostConfig`/`TincBase64` (host file + base64 LE phi chuẩn) |
| Dùng | [Transport.Tcp](../TqkLibrary.VpnClient.Transport.Tcp) | `TcpByteStream` (meta-connection TCP/655, F.1) |
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | (gián tiếp qua Tinc) `AntiReplayWindow` trong `SptpsDatagramRecordLayer` |
| Được dùng bởi | [TqkLibrary.VpnClient](../TqkLibrary.VpnClient) (façade) | `VpnClientBuilder.UseTinc(config)` đăng ký driver |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Drivers.Tinc/
├─ TincDriver.cs                 IVpnProtocolDriver: caps (L3Ip/Noise/Certificate/OutOfBand/Tcp|Udp) + ConnectAsync → TincConnection
├─ TincConnection.cs             Điều phối (kế thừa ReconnectingVpnConnection F.6): TCP meta handshake → ACK/ADD_SUBNET/ADD_EDGE → data-plane SPTPS (REQ_KEY/ANS_KEY) → bind TincChannel → meta+UDP read loop; supervisor/reconnect ở base
├─ TincVpnConnection.cs          IVpnConnection: 1 session point-to-point; OpenSessionAsync ném NotSupportedException
├─ TincVpnSession.cs             IVpnSession: PacketChannel ổn định + TunnelConfig tĩnh
├─ TincReconnectOptions.cs       Kế thừa VpnReconnectOptions (Drivers.Core, F.6)
├─ TincDriverConstants.cs        Port 655, PROT 17.7, MTU 1400, node-id 6B, RouterPacketType 0, ProbePacketType 4, MinProbeSize 3
├─ Config/TincConfig.cs          Ed25519 seed ta + peer host file + overlay IP/CIDR + MTU → ToTunnelConfig() (route = peer Subnet)
├─ Meta/TincMetaConnection.cs    ID + SPTPS meta handshake + meta request I/O (type-0 app record) + TCP data fallback SPTPS_PACKET
├─ DataChannel/
│  ├─ TincNodeId.cs              SHA512(node_name)[:6] (codec thuần)
│  ├─ TincDataTransport.cs       Seal/open data datagram: relay header DSTID(nullid)‖SRCID(node_id) + SptpsDatagramRecordLayer; TryOpenRecord/SealRecord theo type
│  └─ TincChannel.cs             IPacketChannel L3: WriteIpPacketAsync seal → send; Deliver dispatch type 0 (IP)/type 4 (PKT_PROBE → type-2 reply)
└─ Transport/
   ├─ ITincTransportFactory.cs   Seam dựng cặp (TCP meta + UDP data) tới endpoint
   ├─ TincSocketTransportFactory.cs  Production: TcpByteStream meta + UdpClient connected data + UDP receive loop
   └─ TincTransportHandle.cs     Bộ (meta stream, UDP datagram, setReceiver, receivePump)
```

## Bảng chuẩn / RFC / nguồn

| Khía cạnh | Nguồn (clean-room, KHÔNG copy GPL) | Ghi chú |
|-----------|------------------------------------|---------|
| Meta protocol | tinc `protocol_auth.c` (`send_id`/`id_h`/`send_ack`/`ack_h`/`receive_meta_sptps`) | ID `0 <name> 17.7`; ACK `4 <port> <weight> <opts>`; sau ACK server `send_everything` (ADD_SUBNET/ADD_EDGE); initiator KHÔNG gửi empty-ACK record |
| Data-plane key exchange | tinc `protocol_key.c` (`send_req_key`/`req_key_ext_h`/`send_initial_sptps_data`) | SPTPS session riêng; KEX qua `REQ_KEY <me> <peer> 15 <b64>`, SIG qua `ANS_KEY <me> <peer> <b64> -1 -1 -1 0` (type SPTPS_HANDSHAKE) |
| Data packet (router mode) | tinc `net_packet.c` (`send_sptps_data`/`send_sptps_packet`/`handle_incoming_vpn_packet`/`receive_sptps_record`) | type 0 (no PKT_MAC/PKT_COMPRESSED) = bare IP (offset 14 stripped); relay header `DSTID‖SRCID` khi `options>>24>=4` |
| Node id | tinc `node.c` (`node_add`) | `sha512(name); id = hash[:6]` |
| UDP probe | tinc `net_packet.c` (`udp_probe_h`/`send_udp_probe_reply`) | PKT_PROBE type 4; reply `data[0]=2‖len16` (protocol ≥17.3) pad MIN_PROBE_SIZE |
| TCP data fallback | tinc `protocol_misc.c` (`send_sptps_tcppacket`)/`meta.c` (`receive_meta`) | `SPTPS_PACKET <len>` + `<len>` raw bytes (`send_meta_raw`, KHÔNG record-framed) |

## Luồng nội bộ (connect)

1. `TincDriver.ConnectAsync` → `TincConnection.ConnectAsync` → `EstablishAsync`.
2. `ITincTransportFactory.ConnectAsync` → TCP meta (TcpByteStream) + UDP data socket.
3. `TincMetaConnection.HandshakeAsync`: gửi ID → đọc peer ID → SPTPS handshake (KEX→SIG, sau ConsumeSig keyed, KHÔNG empty-ACK).
4. Gửi ACK line + ADD_SUBNET (overlay ta) + ADD_EDGE (client→server, cho graph MST/SSSP).
5. Khởi meta read loop nền + UDP receive loop.
6. `StartDataHandshakeAsync`: data-plane SPTPS initiator → KEX qua REQ_KEY. Khi nhận server KEX (ANS_KEY/REQ_KEY) → ConsumeKex + gửi SIG qua ANS_KEY. Khi nhận server SIG → ConsumeSig → keyed → `BindDataChannel` (TincDataTransport + TincChannel sau facade).
7. `MarkConnected`. Data: `WriteIpPacketAsync` seal → UDP; inbound UDP/TCP-fallback → `Deliver` (type 0 → InboundIpPacket; type 4 PKT_PROBE → type-2 reply).

## Trạng thái & ghi chú

- **OFFLINE**: 10 test [`Drivers.Tinc.Tests`](../../tests/TqkLibrary.VpnClient.Drivers.Tinc.Tests) — `TincDataTransport` (relay header/round-trip 2 chiều/foreign-srcid/tamper/replay/node-id) + `TincConnection` end-to-end vs `SimulatedTincResponder` qua loopback (meta+data handshake + bare-IP echo 2 chiều + responder-originated). Build XANH ns2.0 + net8.
- **VALIDATE LIVE (tincd 1.1pre18 router mode, lab [`tinc`](../../lab/tinc))**: meta SPTPS handshake **activated** + ACK/ADD_SUBNET/ADD_EDGE trao đổi; data-plane SPTPS **keyed**; **UDP probe 2 chiều RTT~2ms**; client ICMP request mã hóa → tới server tun (`10.99.0.2 > 10.99.0.1 echo request`); wire datagram byte-verified hex cả 2 chiều. **5 bug interop self-pair-offline-không-bắt sửa qua live** (meta no-empty-ACK, data SIG qua ANS_KEY, ADD_EDGE cho graph, PKT_PROBE type-2 reply, TCP fallback SPTPS_PACKET — chi tiết ở [`.docs/10`](../../.docs/10-codebase-architecture-and-flow.md) bảng "Khác biệt").
- **RESIDUAL (server-side, KHÔNG phải client)**: full ICMP echo-reply 2 chiều bị chặn ở lab — tincd đọc echo reply (kernel container tự sinh) từ tun nhưng kernel container sinh net-unreachable trên reply tự-sinh (rp_filter/ip_forward/tun NOARP, `/proc/sys` per-interface read-only trong container). Client `TcpIpStack` chỉ sinh code-3 port-unreachable, KHÔNG code-0 net-unreachable ⇒ net-unreachable là của kernel server. Data plane CLIENT đã chứng minh đúng đủ (request-direction + probe 2 chiều + byte-format + server→client delivery). Cần userspace ICMP responder phía server / kernel routing khác để chốt.
- **CHƯA làm (phase b stretch)**: auto-mesh đa-node (route relay nhiều hop), mode L2 switch (`IEthernetChannel`), lighthouse/punchy NAT-traversal, tinc 1.0 legacy (RSA).
