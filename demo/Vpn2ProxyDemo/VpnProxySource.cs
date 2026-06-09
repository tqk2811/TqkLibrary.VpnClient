using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.Vpn.IpStack.Tcp;

namespace Vpn2ProxyDemo
{
    /// <summary>
    /// An <see cref="IProxySource"/> that routes every proxied TCP connection through a VPN tunnel's
    /// userspace IP stack (<see cref="TcpIpStack"/>). Plug it into a <c>TqkLibrary.Proxy.ProxyServer</c>
    /// so an HTTP/SOCKS proxy listening on localhost forwards its traffic out the VPN.
    /// <para>
    /// The userspace stack is IPv4-only and active-open only, so BIND and UDP-ASSOCIATE are not offered
    /// (SOCKS4/5 CONNECT and HTTP/HTTPS CONNECT are fully supported).
    /// </para>
    /// </summary>
    public sealed class VpnProxySource : IProxySource
    {
        readonly TcpIpStack _stack;

        /// <summary>Creates the source over a userspace TCP/IP stack already bound to a connected tunnel.</summary>
        public VpnProxySource(TcpIpStack stack)
        {
            _stack = stack ?? throw new ArgumentNullException(nameof(stack));
        }

        /// <inheritdoc/>
        public bool IsSupportUdp => false;

        /// <inheritdoc/>
        public bool IsSupportIpv6 => false;

        /// <inheritdoc/>
        public bool IsSupportBind => false;

        /// <inheritdoc/>
        public Task<IConnectSource> GetConnectSourceAsync(Guid tunnelId, CancellationToken cancellationToken = default)
            => Task.FromResult<IConnectSource>(new VpnConnectSource(_stack));

        /// <inheritdoc/>
        public Task<IBindSource> GetBindSourceAsync(Guid tunnelId, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("BIND is not supported over the VPN userspace stack (active-open only).");

        /// <inheritdoc/>
        public Task<IUdpAssociateSource> GetUdpAssociateSourceAsync(Guid tunnelId, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("UDP ASSOCIATE is not supported over the VPN userspace stack.");
    }
}
