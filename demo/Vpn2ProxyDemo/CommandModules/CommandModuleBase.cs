using System.CommandLine;
using Vpn2ProxyDemo.CommandModules.Enums;
using Vpn2ProxyDemo.CommandModules.Interfaces;
using Vpn2ProxyDemo.CommandModules.Models;

namespace Vpn2ProxyDemo.CommandModules
{
    /// <summary>
    /// Base chung cho mọi subcommand action của demo VPN. Lo phần dùng chung: option <c>--vpn</c> (URI target), parse
    /// target, in header, connect VPN (giữ vòng đời tunnel tới hết <c>await using</c>), bắt lỗi. Subclass chỉ implement
    /// <see cref="RunAsync"/> — hành động cụ thể trên tunnel đã lên (probe DNS, dựng proxy, ...) và (tùy chọn) override
    /// <see cref="ValidateOptions"/> để fail-fast option riêng trước khi connect.
    /// <para>
    /// Giao thức (SSTP / L2TP) là phần của URI <c>--vpn</c> — KHÔNG phải subcommand. Subcommand tách theo **hành động**;
    /// thêm action mới = thêm một subclass, không sửa base.
    /// </para>
    /// </summary>
    internal abstract class CommandModuleBase : ICommandModule
    {
        Option<string> VpnOption { get; }
        Option<string> WatermarkOption { get; }
        Option<bool> Ipv6Option { get; }
        Option<bool> OuterIpv6Option { get; }
        Option<bool> NativeEspOption { get; }
        Option<int> ExtraSessionsOption { get; }
        Option<bool> Ikev2EapOption { get; }

        readonly Command _command;
        public Command Command => _command;

        protected CommandModuleBase(string name, string description)
        {
            _command = new Command(name, description);

            VpnOption = new Option<string>("--vpn")
            {
                Description = "VPN target. URI scheme://user:pass@host[:port]: scheme = sstp (MS-SSTP/TLS, port 443), "
                    + "l2tp (L2TP/IPsec IKEv1 PSK \"vpn\", NAT-T 500/4500), ikev2 (IKEv2-native RFC 7296, PSK từ ?psk=, "
                    + "ESP tunnel — V.1; thêm --ikev2-eap để EAP-MSCHAPv2 với user:pass), softether|ssl (SoftEther SSL-VPN/TLS 443, "
                    + "?hub= mặc định VPNGATE). Hoặc trỏ thẳng tới một file .ovpn cho OpenVPN, hoặc một file .conf wg-quick "
                    + "cho WireGuard (Noise_IKpsk2/UDP — V.3). Thiếu user:pass ⇒ vpn:vpn.",
                DefaultValueFactory = _ => "sstp://vpn:vpn@public-vpn-226.opengw.net",
            };
            _command.Options.Add(VpnOption);

            WatermarkOption = new Option<string>("--watermark")
            {
                Description = "(Chỉ SoftEther) đường dẫn file chứa watermark blob THẬT của SoftEther — server thật từ "
                    + "chối blob placeholder (HTTP 403). Để trống ⇒ dùng placeholder (chỉ chạy với server giả lập offline).",
                DefaultValueFactory = _ => string.Empty,
            };
            _command.Options.Add(WatermarkOption);

            Ipv6Option = new Option<bool>("--ipv6")
            {
                Description = "Bật IPv6 trong tunnel (IPV6CP + lấy địa chỉ global qua SLAAC/DHCPv6 trên link PPP — P1.1). "
                    + "Chỉ SSTP/L2TP; best-effort: server không cấp IPv6 ⇒ vẫn IPv4 (chỉ thêm ~2s chờ). Mặc định tắt.",
                DefaultValueFactory = _ => false,
            };
            _command.Options.Add(Ipv6Option);

            OuterIpv6Option = new Option<bool>("--outer-ipv6")
            {
                Description = "Ưu tiên IPv6 cho transport NGOÀI — kết nối TỚI server qua IPv6 (resolve AAAA; SSTP=TLS/TCP6, "
                    + "L2TP=IKE/ESP-in-UDP over IPv6) — P1.2. Khác --ipv6 (IPv6 TRONG tunnel). Chỉ SSTP/L2TP; fallback IPv4 nếu "
                    + "host không có AAAA. Mặc định tắt (Auto = IPv4-first, giữ hành vi cũ).",
                DefaultValueFactory = _ => false,
            };
            _command.Options.Add(OuterIpv6Option);

            NativeEspOption = new Option<bool>("--native-esp")
            {
                Description = "(Chỉ L2TP/IPsec) chở ESP gốc trên IP proto-50 (native ESP) cho gateway no-NAT, dưới chế độ "
                    + "NAT-T HonestFirst (P0.8c) thay vì float UDP/4500 — cần quyền raw socket/CAP_NET_RAW (Administrator/root). "
                    + "Scheme khác L2TP ⇒ cờ bị bỏ qua. Mặc định tắt.",
                DefaultValueFactory = _ => false,
            };
            _command.Options.Add(NativeEspOption);

            ExtraSessionsOption = new Option<int>("--l2tp-extra-sessions")
            {
                Description = "(Chỉ L2TP/IPsec) sau khi tunnel lên, mở thêm N phiên L2TP trên CÙNG tunnel/IKE-SA (RFC 2661 "
                    + "multi-session — P1.7) để kiểm chứng mỗi phiên chạy PPP/IPCP riêng → địa chỉ độc lập. Best-effort: đa số "
                    + "remote-access server chỉ cho 1 phiên (đáp CDN). Scheme khác L2TP ⇒ bỏ qua. Mặc định 0.",
                DefaultValueFactory = _ => 0,
            };
            _command.Options.Add(ExtraSessionsOption);

            Ikev2EapOption = new Option<bool>("--ikev2-eap")
            {
                Description = "(Chỉ IKEv2) dùng EAP-MSCHAPv2 (RFC 7296 §2.16) với user:pass của URI thay cho PSK AUTH (V.1). "
                    + "Mặc định tắt ⇒ PSK-only (group PSK từ ?psk=, bỏ qua user:pass). Scheme khác IKEv2 ⇒ bỏ qua.",
                DefaultValueFactory = _ => false,
            };
            _command.Options.Add(Ikev2EapOption);

            _command.SetAction(InvokeAsync);
        }

        async Task<int> InvokeAsync(ParseResult parseResult, CancellationToken ct)
        {
            string vpnUri = parseResult.GetValue(VpnOption)!;

            if (!VpnTarget.TryParse(vpnUri, out VpnTarget? target, out string? vpnError))
            {
                Console.WriteLine($"  !! {vpnError}");
                return 1;
            }
            // Subclass tự validate option riêng (vd proxy-host/port) — fail-fast TRƯỚC khi connect (tránh connect ~90s rồi mới báo lỗi).
            string? optError = ValidateOptions(parseResult);
            if (optError != null)
            {
                Console.WriteLine($"  !! {optError}");
                return 1;
            }

            // Tag protocol cho log/header ("sstp"/"l2tp").
            string tag = target!.Protocol.ToString().ToLowerInvariant();
            PrintHeader(tag);

            string watermarkPath = parseResult.GetValue(WatermarkOption) ?? string.Empty;
            bool enableIpv6 = parseResult.GetValue(Ipv6Option);
            bool preferOuterIpv6 = parseResult.GetValue(OuterIpv6Option);
            bool useNativeEsp = parseResult.GetValue(NativeEspOption);
            int extraSessions = parseResult.GetValue(ExtraSessionsOption);
            bool ikev2Eap = parseResult.GetValue(Ikev2EapOption);

            // --native-esp chỉ áp cho L2TP/IPsec (P0.8c). Bật với scheme khác ⇒ bỏ qua + cảnh báo rõ (không crash).
            if (useNativeEsp && target!.Protocol != VpnProtocol.L2tp)
            {
                Console.WriteLine($"  !! --native-esp chỉ dùng cho L2TP/IPsec; scheme '{tag}' bỏ qua cờ này.");
                useNativeEsp = false;
            }
            // --l2tp-extra-sessions chỉ áp cho L2TP/IPsec (P1.7 multi-session). Scheme khác ⇒ bỏ qua + cảnh báo.
            if (extraSessions > 0 && target!.Protocol != VpnProtocol.L2tp)
            {
                Console.WriteLine($"  !! --l2tp-extra-sessions chỉ dùng cho L2TP/IPsec; scheme '{tag}' bỏ qua.");
                extraSessions = 0;
            }
            // --outer-ipv6 wire cho SSTP/L2TP/IKEv2 ở demo (P1.2). Scheme khác (SoftEther/OpenVPN) cấu hình IPv6 transport
            // theo driver riêng ⇒ bỏ qua + cảnh báo.
            if (preferOuterIpv6 && target!.Protocol != VpnProtocol.Sstp && target.Protocol != VpnProtocol.L2tp && target.Protocol != VpnProtocol.Ikev2)
            {
                Console.WriteLine($"  !! --outer-ipv6 chỉ dùng cho SSTP/L2TP/IKEv2; scheme '{tag}' bỏ qua.");
                preferOuterIpv6 = false;
            }
            // native-ESP (raw proto-50) hiện chỉ strip header IPv4 khi nhận (F.9) ⇒ không chạy trên outer-IPv6.
            // Bật cả hai ⇒ ưu tiên outer-IPv6 (forced NAT-T/UDP), tắt native-ESP + cảnh báo.
            if (preferOuterIpv6 && useNativeEsp)
            {
                Console.WriteLine("  !! --native-esp (raw proto-50) chưa hỗ trợ outer-IPv6; dùng forced NAT-T (UDP) — bỏ --native-esp.");
                useNativeEsp = false;
            }
            // --ikev2-eap chỉ áp cho IKEv2 (V.1). Bật với scheme khác ⇒ bỏ qua + cảnh báo.
            if (ikev2Eap && target!.Protocol != VpnProtocol.Ikev2)
            {
                Console.WriteLine($"  !! --ikev2-eap chỉ dùng cho IKEv2; scheme '{tag}' bỏ qua cờ này.");
                ikev2Eap = false;
            }

            try
            {
                // Connect VPN theo giao thức đã chọn và trả về tunnel (giữ vòng đời kết nối).
                await using VpnTunnel tunnel = await ConnectAsync(target, watermarkPath, enableIpv6, useNativeEsp, extraSessions, preferOuterIpv6, ikev2Eap, ct);

                // Panel "VPN này hỗ trợ gì" — probe (UDP/LAN ảo) + suy luận (IPv6/listen-external) ngay sau khi tunnel lên,
                // TRƯỚC hành động (tự bao timeout, nuốt lỗi nên không làm hỏng lệnh).
                await PrintCapabilitiesAsync(tunnel, ct);

                // Hành động cụ thể của subcommand trên tunnel đã lên.
                await RunAsync(tag, tunnel, parseResult, ct);
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("  (đã hủy)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  !! {ex.GetType().Name}: {ex.Message}");
                Console.WriteLine();
            }

            Console.WriteLine("Done.");
            return 0;
        }

        /// <summary>Hành động cụ thể của subcommand trên <paramref name="tunnel"/> đã lên. Subclass đọc option riêng từ <paramref name="parseResult"/>.</summary>
        protected abstract Task RunAsync(string tag, VpnTunnel tunnel, ParseResult parseResult, CancellationToken ct);

        /// <summary>
        /// In panel "VPN này hỗ trợ gì" (<see cref="VpnCapabilityProbe"/>): probe được thì gửi gói thật (UDP/LAN ảo),
        /// còn lại suy từ địa chỉ cấp + năng lực driver. Bao một chặn-trên thời gian + nuốt mọi lỗi (trừ hủy của caller)
        /// để panel không bao giờ làm hỏng hành động chính.
        /// </summary>
        static async Task PrintCapabilitiesAsync(VpnTunnel tunnel, CancellationToken ct)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(20)); // chặn trên an toàn (mỗi sub-probe đã tự timeout ngắn)
                VpnCapabilityReport report = await VpnCapabilityProbe.RunAsync(tunnel, cts.Token);
                report.Print();
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (OperationCanceledException)
            {
                Console.WriteLine("  (probe khả năng VPN quá thời gian)");
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  (probe khả năng VPN lỗi: {ex.GetType().Name}: {ex.Message})");
                Console.WriteLine();
            }
        }

        /// <summary>Hook validate option riêng của subclass (gọi TRƯỚC khi connect). Trả message lỗi, hoặc <c>null</c> nếu hợp lệ.</summary>
        protected virtual string? ValidateOptions(ParseResult parseResult) => null;

        /// <summary>Dispatch connect theo giao thức đã parse về hàm static tương ứng của <see cref="VpnTunnel"/>.</summary>
        Task<VpnTunnel> ConnectAsync(VpnTarget target, string watermarkPath, bool enableIpv6, bool useNativeEsp, int extraSessions, bool preferOuterIpv6, bool ikev2Eap, CancellationToken ct)
            => target.Protocol switch
            {
                // enableIpv6 chỉ áp cho đường PPP (SSTP/L2TP — P1.1); SoftEther/OpenVPN bật IPv6 theo cấu hình driver riêng.
                // preferOuterIpv6 (P1.2) áp cho SSTP/L2TP/IKEv2 (resolve AAAA + transport ngoài qua IPv6).
                // useNativeEsp + extraSessions chỉ áp cho L2TP/IPsec (P0.8c native ESP / P1.7 multi-session); caller đã chặn scheme khác.
                VpnProtocol.Sstp => VpnTunnel.ConnectSstpAsync(target.Host, target.Port, target.User, target.Pass, ct, enableIpv6, preferOuterIpv6),
                VpnProtocol.L2tp => VpnTunnel.ConnectL2tpAsync(target.Host, target.User, target.Pass, target.PreSharedKey, ct, enableIpv6, useNativeEsp, extraSessions, preferOuterIpv6),
                // IKEv2-native (V.1): PSK group từ ?psk= (như L2TP). --ikev2-eap ⇒ thêm EAP-MSCHAPv2 với user:pass của URI.
                VpnProtocol.Ikev2 => VpnTunnel.ConnectIkev2Async(target.Host, target.PreSharedKey,
                    ikev2Eap ? target.User : null, ikev2Eap ? target.Pass : null, ct, preferOuterIpv6),
                VpnProtocol.SoftEther => VpnTunnel.ConnectSoftEtherAsync(target.Host, target.Port, target.User, target.Pass, target.HubName, watermarkPath, ct),
                VpnProtocol.OpenVpn => VpnTunnel.ConnectOpenVpnAsync(target.ConfigPath!, target.User, target.Pass, ct),
                // WireGuard (V.3): keys/endpoint/address đọc từ file .conf wg-quick (configPath); driver chạy handshake UDP.
                VpnProtocol.WireGuard => VpnTunnel.ConnectWireGuardAsync(target.ConfigPath!, ct),
                _ => throw new ArgumentOutOfRangeException(nameof(target), target.Protocol, "Giao thức VPN không hỗ trợ."),
            };

        void PrintHeader(string protocol)
        {
            Console.WriteLine("============================================================");
            Console.WriteLine($" Vpn2ProxyDemo — Protocol: {protocol}");
            Console.WriteLine("============================================================");
            Console.WriteLine();
        }
    }
}
