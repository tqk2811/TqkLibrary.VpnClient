using System.IO;
using System.Net;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.IpStack.Tcp;

namespace TqkLibrary.VpnClient.Sockets
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

        /// <summary>
        /// Ends the connection immediately with an RST. See <see cref="VpnNetworkStream.Abort"/>
        /// for why abandoning a connection needs this rather than a plain dispose.
        /// </summary>
        public void Abort() => _connection.Abort();
    }
}
