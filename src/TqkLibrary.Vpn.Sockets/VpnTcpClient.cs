using System.IO;
using System.Net;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.IpStack.Tcp;

namespace TqkLibrary.Vpn.Sockets
{
    /// <summary>A TCP client that connects through the VPN tunnel's userspace stack and exposes a <see cref="Stream"/>.</summary>
    public sealed class VpnTcpClient
    {
        readonly TcpConnection _connection;

        VpnTcpClient(TcpConnection connection) => _connection = connection;

        /// <summary>Connects to <paramref name="remoteAddress"/>:<paramref name="remotePort"/> through <paramref name="stack"/>.</summary>
        public static async Task<VpnTcpClient> ConnectAsync(TcpIpStack stack, IPAddress remoteAddress, ushort remotePort, CancellationToken cancellationToken = default)
        {
            TcpConnection connection = await stack.ConnectAsync(remoteAddress, remotePort, cancellationToken).ConfigureAwait(false);
            return new VpnTcpClient(connection);
        }

        /// <summary>Gets the duplex stream for this connection.</summary>
        public Stream GetStream() => new VpnNetworkStream(_connection);
    }
}
