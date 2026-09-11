using Microsoft.Extensions.Logging;
using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.VpnClient.IpStack;

namespace Vpn2ProxyDemo
{
    /// <summary>
    /// An <see cref="IProxySource"/> that routes proxied traffic through a VPN tunnel's userspace IP stack
    /// (<see cref="TcpIpStack"/>). Plug it into a <c>TqkLibrary.Proxy.ProxyServer</c> so an HTTP/SOCKS proxy
    /// listening on localhost forwards its traffic out the VPN.
    /// <para>
    /// Supports SOCKS4/5 + HTTP/HTTPS CONNECT (TCP) and SOCKS5 UDP-ASSOCIATE (datagrams ride the stack's userspace
    /// UDP socket) — the latter through <see cref="IUdpCapable"/>, which is what the server asks since
    /// TqkLibrary.Proxy 1.0.60. Dual-stack when the tunnel provided a global IPv6 address (the stack is built
    /// dual-stack and <see cref="IsSupportIpv6"/> is set; otherwise IPv4-only). BIND is not offered — the source does
    /// not implement <see cref="IBindCapable"/>, so the server refuses it: the stack is active-open only, and the
    /// private tunnel address is not routable from the internet, so an external peer could never dial in.
    /// </para>
    /// <para>
    /// Does not own the stack: the <c>VpnTunnel</c> that built it closes it, so <see cref="DisposeAsync"/> has
    /// nothing to release.
    /// </para>
    /// </summary>
    public sealed partial class VpnProxySource : IProxySource, IUdpCapable
    {
        readonly TcpIpStack _stack;
        readonly ILoggerFactory? _loggerFactory;
        readonly bool _supportIpv6;

        /// <summary>Creates the source over a userspace TCP/IP stack already bound to a connected tunnel.</summary>
        /// <param name="loggerFactory">Optional — sinh logger cho mỗi connect/UDP-associate source (null = không log).</param>
        /// <param name="supportIpv6">True khi tunnel có IPv6 global (stack dual-stack) — bật egress IPv6 cho proxy (P1.1).</param>
        public VpnProxySource(TcpIpStack stack, ILoggerFactory? loggerFactory = null, bool supportIpv6 = false)
        {
            _stack = stack ?? throw new ArgumentNullException(nameof(stack));
            _loggerFactory = loggerFactory;
            _supportIpv6 = supportIpv6;
        }

        /// <summary>
        /// Whether the tunnel's stack is dual-stack (the tunnel handed out a global IPv6 address). Informational:
        /// no part of TqkLibrary.Proxy asks a source this. Whether an IPv6 destination can be reached is decided by
        /// the stack itself, which is why this source does not offer the <see cref="IAddressFamilyPolicy"/> switch.
        /// </summary>
        public bool IsSupportIpv6 => _supportIpv6;

        /// <inheritdoc/>
        public bool IsSupportUdp => true;

        /// <inheritdoc/>
        public Task<IConnectSource> GetConnectSourceAsync(Guid tunnelId, CancellationToken cancellationToken = default)
            => Task.FromResult<IConnectSource>(new VpnConnectSource(_stack, _loggerFactory?.CreateLogger<VpnConnectSource>()));

        /// <inheritdoc/>
        public Task<IUdpAssociateSource> GetUdpAssociateSourceAsync(Guid tunnelId, CancellationToken cancellationToken = default)
            => Task.FromResult<IUdpAssociateSource>(new VpnUdpAssociateSource(_stack, _loggerFactory?.CreateLogger<VpnUdpAssociateSource>()));

        /// <summary>Nothing to release: the stack belongs to the tunnel that built it.</summary>
        public ValueTask DisposeAsync() => default;
    }
}
