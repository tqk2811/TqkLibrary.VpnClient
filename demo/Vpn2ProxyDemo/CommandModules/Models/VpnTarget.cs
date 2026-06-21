using Vpn2ProxyDemo.CommandModules.Enums;

namespace Vpn2ProxyDemo.CommandModules.Models
{
    /// <summary>
    /// Tham số kết nối VPN parse từ option <c>--vpn</c>. Có hai dạng:
    /// <list type="bullet">
    /// <item>URI <c>scheme://user:pass@host[:port][?psk=...][?hub=...]</c> cho SSTP/L2TP/SoftEther.</item>
    /// <item>Đường dẫn một file <c>.ovpn</c> (kết thúc bằng <c>.ovpn</c>) cho OpenVPN — host/port/proto/chứng chỉ đọc từ chính file.</item>
    /// </list>
    /// <para>
    /// <c>scheme</c> → <see cref="VpnProtocol"/> (<c>sstp</c>/<c>l2tp</c>/<c>softether</c>|<c>ssl</c>), <c>user:pass</c> →
    /// credential (thiếu thì mặc định <c>vpn:vpn</c> kiểu VPN Gate), <c>host</c> → địa chỉ gateway, <c>port</c> → cổng
    /// (SSTP/SoftEther default 443; L2TP/IPsec cố định NAT-T 500/4500 nên bỏ qua port), <c>?psk=</c> → pre-shared key
    /// (chỉ L2TP/IPsec, default <c>vpn</c>), <c>?hub=</c> → Virtual Hub (chỉ SoftEther, default <c>VPNGATE</c> kiểu VPN Gate).
    /// </para>
    /// </summary>
    internal sealed class VpnTarget
    {
        public VpnTarget(VpnProtocol protocol, string host, int port, string user, string pass,
            string preSharedKey = "vpn", string hubName = "VPNGATE", string? configPath = null)
        {
            Protocol = protocol;
            Host = host;
            Port = port;
            User = user;
            Pass = pass;
            PreSharedKey = preSharedKey;
            HubName = hubName;
            ConfigPath = configPath;
        }

        public VpnProtocol Protocol { get; }
        public string Host { get; }

        /// <summary>Cổng gateway. Với SSTP/SoftEther đã áp default 443 nếu URI không ghi; L2TP bỏ qua giá trị này.</summary>
        public int Port { get; }
        public string User { get; }
        public string Pass { get; }

        /// <summary>Pre-shared key IKEv1 (group PSK). Chỉ L2TP/IPsec dùng; thiếu <c>?psk=</c> ⇒ mặc định <c>vpn</c> (VPN Gate).</summary>
        public string PreSharedKey { get; }

        /// <summary>Virtual Hub của SoftEther. Chỉ SoftEther dùng; thiếu <c>?hub=</c> ⇒ mặc định <c>VPNGATE</c> (VPN Gate).</summary>
        public string HubName { get; }

        /// <summary>Đường dẫn file <c>.ovpn</c>. Chỉ OpenVPN dùng (host/port/proto/chứng chỉ đọc từ file); null với giao thức khác.</summary>
        public string? ConfigPath { get; }

        /// <summary>
        /// Parse <c>--vpn</c>: một đường dẫn <c>.ovpn</c> (OpenVPN) hoặc URI <c>scheme://user:pass@host[:port][?psk=][?hub=]</c>.
        /// Trả <c>false</c> + <paramref name="error"/> nếu rỗng/không hợp lệ, scheme không hỗ trợ, hoặc thiếu host. Thiếu
        /// <c>user:pass</c> ⇒ <c>vpn:vpn</c>; SSTP/SoftEther thiếu port ⇒ 443; L2TP thiếu <c>?psk=</c> ⇒ <c>vpn</c>;
        /// SoftEther thiếu <c>?hub=</c> ⇒ <c>VPNGATE</c>.
        /// </summary>
        public static bool TryParse(string value, out VpnTarget? target, out string? error)
        {
            target = null;
            error = null;

            if (string.IsNullOrWhiteSpace(value))
            {
                error = "--vpn trống. Cần URI scheme://user:pass@host[:port] (vd sstp://vpn:vpn@public-vpn-226.opengw.net) "
                    + "hoặc đường dẫn một file .ovpn (OpenVPN).";
                return false;
            }

            // Dạng OpenVPN: --vpn trỏ thẳng tới một file .ovpn (host/port/proto/chứng chỉ nằm trong file, không phải URI).
            if (value.Trim().EndsWith(".ovpn", StringComparison.OrdinalIgnoreCase))
            {
                target = new VpnTarget(VpnProtocol.OpenVpn, host: value.Trim(), port: 0, user: "", pass: "", configPath: value.Trim());
                return true;
            }

            if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri))
            {
                error = $"--vpn '{value}' không phải URI hợp lệ. Cần scheme://user:pass@host[:port] hoặc đường dẫn .ovpn.";
                return false;
            }
            // scheme → giao thức. "ssl" là alias của SoftEther (VPN Gate gọi giao thức SoftEther là "SSL-VPN").
            VpnProtocol protocol;
            if (string.Equals(uri.Scheme, "ssl", StringComparison.OrdinalIgnoreCase))
                protocol = VpnProtocol.SoftEther;
            else if (!Enum.TryParse(uri.Scheme, ignoreCase: true, out protocol) || protocol == VpnProtocol.OpenVpn)
            {
                error = $"--vpn scheme '{uri.Scheme}' không hỗ trợ. Dùng 'sstp', 'l2tp', 'softether'/'ssl', hoặc trỏ tới một file .ovpn cho OpenVPN.";
                return false;
            }
            if (string.IsNullOrEmpty(uri.Host))
            {
                error = $"--vpn '{value}' thiếu host.";
                return false;
            }

            // user:pass (percent-decoded). Thiếu ⇒ vpn:vpn (mặc định VPN Gate).
            string user = "vpn";
            string pass = "vpn";
            string userInfo = uri.UserInfo;
            if (!string.IsNullOrEmpty(userInfo))
            {
                int sep = userInfo.IndexOf(':');
                if (sep < 0)
                {
                    user = Uri.UnescapeDataString(userInfo);
                }
                else
                {
                    user = Uri.UnescapeDataString(userInfo.Substring(0, sep));
                    pass = Uri.UnescapeDataString(userInfo.Substring(sep + 1)); // password được phép chứa ':'
                }
                if (string.IsNullOrEmpty(user)) user = "vpn";
            }

            int port = uri.Port; // -1 nếu URI không ghi port
            if ((protocol == VpnProtocol.Sstp || protocol == VpnProtocol.SoftEther) && port < 0) port = 443;

            // PSK từ ?psk=... (L2TP) + Hub từ ?hub=... (SoftEther) — percent-decoded; thiếu ⇒ áp default trong ctor.
            string? psk = TryGetQueryValue(uri.Query, "psk");
            string? hub = TryGetQueryValue(uri.Query, "hub");
            target = new VpnTarget(protocol, uri.Host, port, user, pass,
                preSharedKey: string.IsNullOrEmpty(psk) ? "vpn" : psk!,
                hubName: string.IsNullOrEmpty(hub) ? "VPNGATE" : hub!);
            return true;
        }

        /// <summary>Lấy giá trị (percent-decoded) của 1 key trong query string <c>?a=1&amp;b=2</c>; không có ⇒ <c>null</c>. Pure helper.</summary>
        static string? TryGetQueryValue(string query, string key)
        {
            if (string.IsNullOrEmpty(query)) return null;
            foreach (string pair in query.TrimStart('?').Split('&'))
            {
                if (pair.Length == 0) continue;
                int eq = pair.IndexOf('=');
                string k = eq < 0 ? pair : pair.Substring(0, eq);
                if (string.Equals(Uri.UnescapeDataString(k), key, StringComparison.OrdinalIgnoreCase))
                    return eq < 0 ? string.Empty : Uri.UnescapeDataString(pair.Substring(eq + 1));
            }
            return null;
        }
    }
}
