using TqkLibrary.Vpn.IpStack.Tcp;

namespace Vpn2ProxyDemo.CommandModules
{
    /// <summary>
    /// Một tunnel VPN đã kết nối, lộ ra userspace <see cref="TcpIpStack"/> để chạy proxy bên trong tunnel.
    /// <para>
    /// Không trả thẳng <see cref="TcpIpStack"/> được vì stack bám vào kết nối VPN bên dưới (SSTP/L2TP) — kết nối
    /// đó phải sống tới khi proxy dùng xong. <see cref="VpnTunnel"/> giữ lại handle teardown: <see cref="DisposeAsync"/>
    /// sẽ đóng kết nối VPN.
    /// </para>
    /// </summary>
    internal sealed class VpnTunnel : IAsyncDisposable
    {
        readonly Func<ValueTask> _disposeAsync;

        public VpnTunnel(TcpIpStack stack, Func<ValueTask> disposeAsync)
        {
            Stack = stack ?? throw new ArgumentNullException(nameof(stack));
            _disposeAsync = disposeAsync ?? throw new ArgumentNullException(nameof(disposeAsync));
        }

        /// <summary>Userspace TCP/IP stack chạy trong tunnel — dùng làm ctor của <c>VpnProxySource</c>.</summary>
        public TcpIpStack Stack { get; }

        public ValueTask DisposeAsync() => _disposeAsync();
    }
}
