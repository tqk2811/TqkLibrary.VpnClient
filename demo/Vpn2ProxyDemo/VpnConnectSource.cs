using System.IO;
using System.Net;
using System.Net.Sockets;
using TqkLibrary.Proxy.Exceptions;
using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.Vpn.IpStack.Tcp;
using TqkLibrary.Vpn.Sockets;

namespace Vpn2ProxyDemo
{
    /// <summary>
    /// One proxied TCP connection opened through the VPN tunnel. <see cref="ConnectAsync"/> resolves the
    /// target host to an IPv4 address, then dials it through the userspace stack; <see cref="GetStreamAsync"/>
    /// returns the in-tunnel duplex byte stream the proxy pipes the client's traffic over.
    /// </summary>
    public sealed class VpnConnectSource : IConnectSource
    {
        readonly TcpIpStack _stack;
        Stream? _stream;
        bool _disposed;

        internal VpnConnectSource(TcpIpStack stack)
        {
            _stack = stack;
        }

        /// <summary>
        /// Opens a TCP connection to <paramref name="address"/> through the tunnel. The host is resolved to
        /// IPv4 via host DNS (the exit IP is determined by the tunnel, not by where DNS runs); the TCP bytes
        /// then travel entirely inside the VPN.
        /// </summary>
        public async Task ConnectAsync(Uri address, CancellationToken cancellationToken = default)
        {
            if (address is null) throw new ArgumentNullException(nameof(address));
            if (_disposed) throw new ObjectDisposedException(nameof(VpnConnectSource));

            int port = address.Port >= 0
                ? address.Port
                : (Uri.UriSchemeHttps.Equals(address.Scheme, StringComparison.OrdinalIgnoreCase) ? 443 : 80);

            IPAddress ip = await ResolveIpv4Async(address.Host, address.HostNameType).ConfigureAwait(false);
            try
            {
                VpnTcpClient client = await VpnTcpClient.ConnectAsync(_stack, ip, (ushort)port, cancellationToken).ConfigureAwait(false);
                _stream = client.GetStream();
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new InitConnectSourceFailedException($"Failed to connect to {address.Host}:{port} ({ip}) through the VPN tunnel: {ex.Message}");
            }
        }

        /// <inheritdoc/>
        public Task<Stream> GetStreamAsync(CancellationToken cancellationToken = default)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(VpnConnectSource));
            if (_stream is null) throw new InvalidOperationException($"Call {nameof(ConnectAsync)} first.");
            return Task.FromResult(_stream);
        }

        static async Task<IPAddress> ResolveIpv4Async(string host, UriHostNameType hostType)
        {
            switch (hostType)
            {
                case UriHostNameType.IPv4:
                    return IPAddress.Parse(host);

                case UriHostNameType.IPv6:
                    throw new NotSupportedException("IPv6 is not supported over the VPN userspace stack.");

                case UriHostNameType.Dns:
                    IPAddress[] ips = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
                    IPAddress? v4 = ips.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                    return v4 ?? throw new InitConnectSourceFailedException($"No IPv4 address resolved for host '{host}'.");

                default:
                    throw new NotSupportedException($"Unsupported host name type '{hostType}'.");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _stream?.Dispose();
            _stream = null;
        }
    }
}
