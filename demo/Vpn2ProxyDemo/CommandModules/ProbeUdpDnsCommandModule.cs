using System.CommandLine;
using System.Net;
using TqkLibrary.Vpn.IpStack;

namespace Vpn2ProxyDemo.CommandModules
{
    /// <summary>
    /// Subcommand <c>dns</c>: gửi một truy vấn DNS (bản ghi A) qua <b>UDP xuyên tunnel</b> — vừa kiểm tra VPN có định
    /// tuyến UDP hay không, vừa phân giải <c>--resolve</c> ra IPv4. Không dựng proxy (xem subcommand <c>proxy</c>).
    /// </summary>
    internal sealed class ProbeUdpDnsCommandModule : CommandModuleBase
    {
        Option<string> DnsServerOption { get; }
        Option<string> ResolveOption { get; }

        public ProbeUdpDnsCommandModule() : base("dns", "Probe UDP + phân giải DNS-over-UDP qua tunnel (kiểm tra VPN có hỗ trợ UDP).")
        {
            DnsServerOption = new Option<string>("--dns-server")
            {
                Description = "DNS server (IPv4) cho phép thử UDP qua tunnel. Bỏ trống = dùng DNS do VPN cấp, fallback 8.8.8.8.",
                DefaultValueFactory = _ => "",
            };
            ResolveOption = new Option<string>("--resolve")
            {
                Description = "Tên miền phân giải bằng DNS-over-UDP qua tunnel (đồng thời kiểm tra VPN có hỗ trợ UDP).",
                DefaultValueFactory = _ => "google.com",
            };
            Command.Options.Add(DnsServerOption);
            Command.Options.Add(ResolveOption);
        }

        protected override Task RunAsync(string tag, VpnTunnel tunnel, ParseResult parseResult, CancellationToken ct)
        {
            string dnsServer = parseResult.GetValue(DnsServerOption)!;
            string resolveDomain = parseResult.GetValue(ResolveOption)!;
            return ProbeUdpDnsAsync(tag, tunnel.Stack, tunnel.AssignedDns, dnsServer, resolveDomain, ct);
        }

        /// <summary>
        /// Gửi một truy vấn DNS (bản ghi A) cho <paramref name="domain"/> qua UDP xuyên tunnel để kiểm tra VPN có
        /// định tuyến UDP hay không, và in IPv4 phân giải được. Đích DNS: <paramref name="dnsServerOpt"/> nếu là IP
        /// hợp lệ; ngược lại dùng DNS do VPN cấp (<paramref name="assignedDns"/>), fallback 8.8.8.8. Lỗi chỉ in cảnh báo.
        /// </summary>
        async Task ProbeUdpDnsAsync(string tag, TcpIpStack stack, IPAddress? assignedDns, string dnsServerOpt, string domain, CancellationToken ct)
        {
            IPAddress dnsServer = !string.IsNullOrWhiteSpace(dnsServerOpt) && IPAddress.TryParse(dnsServerOpt, out IPAddress? parsed)
                ? parsed
                : assignedDns ?? IPAddress.Parse("8.8.8.8");

            Console.WriteLine($"[{tag}] UDP test: gửi truy vấn DNS (A) cho '{domain}' tới {dnsServer}:53 qua tunnel...");
            try
            {
                UdpDnsProbeResult result = await UdpDnsProbe.ResolveAsync(
                    stack, dnsServer, domain, attempts: 3, perAttemptTimeout: TimeSpan.FromSeconds(3), ct);

                if (result.UdpSupported)
                {
                    Console.WriteLine($"[{tag}] => VPN HỖ TRỢ UDP (nhận phản hồi ở lần thử {result.Attempts}, {result.Elapsed.TotalMilliseconds:F0} ms).");
                    if (result.Addresses.Count > 0)
                        Console.WriteLine($"[{tag}] => {domain} = {string.Join(", ", result.Addresses)}");
                    else
                        Console.WriteLine($"[{tag}] => (không có bản ghi A: {result.Error})");
                }
                else
                {
                    Console.WriteLine($"[{tag}] => VPN có thể KHÔNG hỗ trợ/định tuyến UDP: {result.Error} (đã chờ {result.Elapsed.TotalMilliseconds:F0} ms).");
                    Console.WriteLine($"[{tag}]    (cũng có thể do DNS server {dnsServer} không reachable — thử --dns-server khác).");
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{tag}] UDP test lỗi: {ex.GetType().Name}: {ex.Message}");
            }
            Console.WriteLine();
        }
    }
}
