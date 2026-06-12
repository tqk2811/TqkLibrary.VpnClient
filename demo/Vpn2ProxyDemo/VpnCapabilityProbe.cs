using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.Vpn.Abstractions.Drivers.Enums;
using TqkLibrary.Vpn.Abstractions.Drivers.Models;
using TqkLibrary.Vpn.IpStack;

namespace Vpn2ProxyDemo
{
    /// <summary>
    /// Probe + suy luận "VPN này hỗ trợ gì" để in panel ngay sau khi tunnel lên. Phần <b>probe được</b> thì gửi gói thật
    /// qua tunnel (UDP qua DNS-over-UDP — tái dùng <see cref="UdpDnsProbe"/>; LAN ảo qua ICMP ping gateway nội bộ —
    /// <see cref="TqkLibrary.Vpn.IpStack.TcpIpStack.PingAsync"/>); phần <b>chưa probe được</b> thì suy từ địa chỉ
    /// được cấp + năng lực driver (<see cref="VpnDriverCapabilities"/>): IPv6 (chưa có IPv6CP), listen-external (NAT).
    /// <para>
    /// Mỗi sub-probe tự bao timeout ngắn và KHÔNG ném khi hết giờ (trả <see cref="CapabilityStatus.Unknown"/>/
    /// <see cref="CapabilityStatus.Unlikely"/>) — chỉ propagate hủy từ <paramref name="cancellationToken"/> của caller.
    /// </para>
    /// </summary>
    internal static class VpnCapabilityProbe
    {
        /// <summary>Chạy toàn bộ probe + suy luận trên <paramref name="tunnel"/> đã lên, trả panel để <see cref="VpnCapabilityReport.Print"/>.</summary>
        public static async Task<VpnCapabilityReport> RunAsync(VpnTunnel tunnel, CancellationToken cancellationToken = default)
        {
            VpnDriverCapabilities caps = tunnel.Capabilities;
            IPAddress ip = tunnel.AssignedAddress;
            (string scope, bool behindNat) = ClassifyV4(ip);

            // Probe trước để biết LAN ảo (kèm gateway phát hiện) rồi mới dựng Info — gateway chỉ hiển thị khi CÓ LAN ảo.
            VpnCapability udp = await ProbeUdpAsync(tunnel, cancellationToken).ConfigureAwait(false);
            (VpnCapability lan, IPAddress? gateway, string gatewayNote) = await ProbeVirtualLanAsync(tunnel, ip, caps, cancellationToken).ConfigureAwait(false);

            var info = new List<(string, string)>
            {
                ("IP ảo", $"{ip}  ({scope})"),
                ("DNS", tunnel.AssignedDns?.ToString() ?? "(không cấp)"),
            };
            // Thêm gateway nếu phát hiện LAN ảo (ngay dưới DNS cho dễ đọc).
            if (gateway is not null)
                info.Add(("Gateway nội bộ", $"{gateway}  ({gatewayNote})"));
            info.Add(("MTU tunnel", tunnel.Mtu.ToString()));
            info.Add(("Transport", DescribeTransport(caps.TransportKinds)));
            info.Add(("Bảo mật", DescribeSecurity(caps.SecurityKinds)));
            info.Add(("Xác thực", DescribeAuth(caps)));
            info.Add(("Cấp địa chỉ", caps.AddressAssignment == AddressAssignment.Ipcp ? "IPCP (PPP)" : caps.AddressAssignment.ToString()));

            var list = new List<VpnCapability>
            {
                // 1) IPv4 routing — đã có IP ảo nên coi như có (toàn bộ demo proxy/HTTP chứng minh).
                new VpnCapability("IPv4 routing", CapabilityStatus.Yes, $"IP ảo {ip} đã cấp + định tuyến qua tunnel"),

                // 2) IPv6 — PPP chỉ chạy IPCP (IPv4); chưa có IPv6CP ⇒ tunnel không có nguồn địa chỉ IPv6.
                new VpnCapability("IPv6", CapabilityStatus.No,
                    "PPP chỉ negotiate IPCP (IPv4); chưa có IPv6CP ⇒ không có địa chỉ IPv6 (thư viện: roadmap P1.1)"),

                // 3) UDP — probe thật: DNS-over-UDP xuyên tunnel.
                udp,

                // 4) Listen TCP (mở port ra internet) — sau NAT + stack chưa có TCP passive-open.
                new VpnCapability("Listen TCP (mở port ra internet)", CapabilityStatus.No, DescribeListenTcp(behindNat, scope)),

                // 5) Listen UDP (mở port ra internet) — sau NAT + UdpConnection là connected-UDP.
                new VpnCapability("Listen UDP (mở port ra internet)", CapabilityStatus.No, DescribeListenUdp(behindNat, scope)),

                // 6) LAN ảo trong VPN — probe ICMP gateway nội bộ + heuristic DNS cùng subnet.
                lan,

                // 7) MAC address (L2) — driver L3 point-to-point (PPP/IPCP) không có khung Ethernet ⇒ không có MAC.
                new VpnCapability("MAC address (L2)",
                    caps.LinkLayer == VpnLinkLayer.L3Ip ? CapabilityStatus.No : CapabilityStatus.Unknown,
                    caps.LinkLayer == VpnLinkLayer.L3Ip
                        ? "driver chạy L3 point-to-point (PPP/IPCP) — không có khung Ethernet ⇒ không có MAC; tầng L2 (MacAddress/EthernetSwitch) đã có nhưng chưa driver nào dùng (thư viện: roadmap L2.x, driver L2 đầu: SoftEther V.4)"
                        : $"driver khai LinkLayer.{caps.LinkLayer}; demo chưa đọc LinkAddress từ kênh L2"),
            };

            return new VpnCapabilityReport(tunnel.ProtocolName, info, list);
        }

        /// <summary>Probe UDP: gửi DNS-over-UDP xuyên tunnel (tái dùng <see cref="UdpDnsProbe"/>). Nhận phản hồi ⇒ Yes.</summary>
        static async Task<VpnCapability> ProbeUdpAsync(VpnTunnel tunnel, CancellationToken ct)
        {
            IPAddress dns = tunnel.AssignedDns ?? IPAddress.Parse("8.8.8.8");
            try
            {
                UdpDnsProbeResult r = await UdpDnsProbe.ResolveAsync(
                    tunnel.Stack, dns, "google.com", attempts: 2, perAttemptTimeout: TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                return r.UdpSupported
                    ? new VpnCapability("UDP", CapabilityStatus.Yes, $"nhận phản hồi DNS-over-UDP từ {dns} ({r.Elapsed.TotalMilliseconds:F0} ms)")
                    : new VpnCapability("UDP", CapabilityStatus.Unlikely, $"không nhận phản hồi UDP từ {dns} (server chặn UDP? hoặc DNS không reachable)");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                return new VpnCapability("UDP", CapabilityStatus.Unknown, $"probe lỗi: {ex.GetType().Name}: {ex.Message}");
            }
        }

        /// <summary>
        /// Probe LAN ảo: ping (ICMP) gateway nội bộ suy đoán (DNS nếu cùng /24, ngược lại <c>x.y.z.1</c>). Có phản hồi/host
        /// trả lời ⇒ Likely. Driver hiện model điểm-điểm (<see cref="MultiHostModel.None"/>) nên đây là LAN phía server (SecureNAT).
        /// <para>Trả kèm <c>Gateway</c> (≠ null khi PHÁT HIỆN LAN ảo) + <c>GatewayNote</c> (cách phát hiện) để panel thêm dòng "Gateway nội bộ".</para>
        /// </summary>
        static async Task<(VpnCapability Cap, IPAddress? Gateway, string GatewayNote)> ProbeVirtualLanAsync(
            VpnTunnel tunnel, IPAddress ip, VpnDriverCapabilities caps, CancellationToken ct)
        {
            const string name = "LAN ảo trong VPN";
            if (ip.AddressFamily != AddressFamily.InterNetwork)
                return (new VpnCapability(name, CapabilityStatus.Unknown, "không có địa chỉ IPv4 để dò"), null, "");

            byte[] octets = ip.GetAddressBytes();
            IPAddress? dns = tunnel.AssignedDns;
            bool dnsInSubnet = dns is not null && SameSlash24(octets, dns.GetAddressBytes());
            IPAddress gateway = dnsInSubnet ? dns! : new IPAddress(new byte[] { octets[0], octets[1], octets[2], 1 });
            string subnet = $"{octets[0]}.{octets[1]}.{octets[2]}.0/24";

            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(3));
                PingReply reply = await tunnel.Stack.PingAsync(gateway, cancellationToken: cts.Token).ConfigureAwait(false);
                return (new VpnCapability(name, CapabilityStatus.Likely,
                        $"host nội bộ {gateway} trả lời ICMP (RTT {reply.RoundTripTime.TotalMilliseconds:F0} ms) trong {subnet} — có hub/LAN nội bộ"),
                    gateway, $"ICMP reachable, RTT {reply.RoundTripTime.TotalMilliseconds:F0} ms");
            }
            catch (IcmpUnreachableException)
            {
                // Có thiết bị nội bộ trả lời Destination Unreachable ⇒ vẫn cho thấy có host trong subnet.
                return (new VpnCapability(name, CapabilityStatus.Likely, $"có host nội bộ {gateway} trong {subnet} trả lời ICMP (unreachable)"),
                    gateway, "trả lời ICMP (unreachable)");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (OperationCanceledException)
            {
                // Hết giờ ping (không phải hủy từ caller).
                return dnsInSubnet
                    ? (new VpnCapability(name, CapabilityStatus.Likely, $"DNS {dns} cùng subnet {subnet} (gateway nội bộ) nhưng {gateway} không trả ICMP"),
                        gateway, "suy đoán: DNS cùng subnet, không trả ICMP")
                    : (new VpnCapability(name, CapabilityStatus.Unknown, $"không thấy host nội bộ trong {subnet}; driver model điểm-điểm (MultiHostModel.{caps.MultiHostModel})"),
                        null, "");
            }
            catch (Exception ex)
            {
                return (new VpnCapability(name, CapabilityStatus.Unknown, $"probe lỗi: {ex.GetType().Name}: {ex.Message}"), null, "");
            }
        }

        /// <summary>So 3 octet đầu (cùng /24) của 2 địa chỉ IPv4.</summary>
        static bool SameSlash24(byte[] a, byte[] b) =>
            a.Length == 4 && b.Length == 4 && a[0] == b[0] && a[1] == b[1] && a[2] == b[2];

        /// <summary>Phân loại địa chỉ IPv4 được cấp → mô tả scope + có sau NAT không (driving heuristic listen-external).</summary>
        static (string scope, bool behindNat) ClassifyV4(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return (ip.AddressFamily.ToString(), true);
            byte[] o = ip.GetAddressBytes();
            if (o[0] == 10) return ("private RFC1918", true);
            if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) return ("private RFC1918", true);
            if (o[0] == 192 && o[1] == 168) return ("private RFC1918", true);
            if (o[0] == 100 && o[1] >= 64 && o[1] <= 127) return ("CGNAT RFC6598", true);
            if (o[0] == 169 && o[1] == 254) return ("link-local", true);
            if (o[0] == 127) return ("loopback", true);
            return ("public", false);
        }

        static string DescribeTransport(VpnTransportKind k)
        {
            if (k.HasFlag(VpnTransportKind.Tls)) return "TLS / TCP 443";
            if (k.HasFlag(VpnTransportKind.Udp)) return "UDP (NAT-T 500↔4500)";
            return k.ToString();
        }

        static string DescribeSecurity(VpnSecurityKind k)
        {
            if (k.HasFlag(VpnSecurityKind.Tls)) return "TLS";
            if (k.HasFlag(VpnSecurityKind.Esp)) return "IPsec ESP";
            return k.ToString();
        }

        static string DescribeAuth(VpnDriverCapabilities caps)
        {
            // Cả 2 driver hiện tại đều mang PPP → user/password xác thực bằng MS-CHAPv2.
            string s = caps.UsesPpp ? "MS-CHAPv2 (user/password)" : caps.AuthMethods.ToString();
            if (caps.AuthMethods.HasFlag(VpnAuthMethod.PreSharedKey)) s += " + PSK (IKEv1 group key)";
            return s;
        }

        static string DescribeListenTcp(bool behindNat, string scope) =>
            behindNat
                ? $"IP ảo {scope} ⇒ sau NAT, peer ngoài không dial vào; ngoài ra stack chỉ active-open, chưa có TCP listener/accept (thư viện)"
                : "stack hiện chỉ active-open, chưa có TCP passive-open/listener (thư viện)";

        static string DescribeListenUdp(bool behindNat, string scope) =>
            behindNat
                ? $"IP ảo {scope} ⇒ sau NAT, peer ngoài không gửi vào; ngoài ra UdpConnection là connected-UDP (lọc 1 remote), chưa nhận-từ-mọi-nguồn (thư viện)"
                : "UdpConnection là connected-UDP (lọc 1 remote), chưa có bind nhận-từ-mọi-nguồn (thư viện)";
    }
}
