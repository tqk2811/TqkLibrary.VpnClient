using System.CommandLine;

namespace Vpn2ProxyDemo.CommandModules
{
    /// <summary>
    /// Base cho các dạng VPN cấu hình bằng <c>host + user + pass</c> (SSTP, L2TP/IPsec, ... — kiểu VPN Gate).
    /// Thêm sẵn 3 option <c>--host/--user/--pass</c> (default theo VPN Gate), đọc chúng và gọi
    /// <see cref="ConnectAsync(string,string,string,System.Threading.CancellationToken)"/> của lớp con.
    /// <para>Dạng VPN dùng credential khác (cert, config file, key...) thì kế thừa thẳng <see cref="CommandModuleBase"/>.</para>
    /// </summary>
    internal abstract class HostCredentialCommandModuleBase : CommandModuleBase
    {
        protected Option<string> HostOption { get; }
        protected Option<string> UserOption { get; }
        protected Option<string> PassOption { get; }

        protected HostCredentialCommandModuleBase(string name, string description) : base(name, description)
        {
            HostOption = new Option<string>("--host")
            {
                Description = "Host VPN Gate (hỗ trợ MS-SSTP / L2TP).",
                DefaultValueFactory = _ => "public-vpn-226.opengw.net",
            };
            UserOption = new Option<string>("--user")
            {
                Description = "Tài khoản VPN.",
                DefaultValueFactory = _ => "vpn",
            };
            PassOption = new Option<string>("--pass")
            {
                Description = "Mật khẩu VPN.",
                DefaultValueFactory = _ => "vpn",
            };

            Command.Options.Add(HostOption);
            Command.Options.Add(UserOption);
            Command.Options.Add(PassOption);
        }

        protected sealed override Task<VpnTunnel> ConnectAsync(ParseResult parseResult, CancellationToken ct)
            => ConnectAsync(
                parseResult.GetValue(HostOption)!,
                parseResult.GetValue(UserOption)!,
                parseResult.GetValue(PassOption)!,
                ct);

        /// <summary>Connect VPN bằng host/user/pass đã parse; trả về tunnel đã lên (đang sống).</summary>
        protected abstract Task<VpnTunnel> ConnectAsync(string host, string user, string pass, CancellationToken ct);
    }
}
