using System.Net;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.IpStack.Udp;

namespace TqkLibrary.Vpn.Sockets
{
    /// <summary>
    /// A connected UDP client over the VPN tunnel's userspace stack: datagrams are sent to a fixed remote endpoint
    /// and <see cref="ReceiveAsync"/> returns replies from it (datagrams from other sources are ignored).
    /// </summary>
    public sealed class VpnUdpClient
    {
        readonly UdpConnection _socket;
        readonly IPAddress _remoteAddress;
        readonly ushort _remotePort;

        VpnUdpClient(UdpConnection socket, IPAddress remoteAddress, ushort remotePort)
        {
            _socket = socket;
            _remoteAddress = remoteAddress;
            _remotePort = remotePort;
        }

        /// <summary>The bound local UDP port.</summary>
        public ushort LocalPort => _socket.LocalPort;

        /// <summary>Binds a UDP socket on <paramref name="stack"/> targeting <paramref name="remoteAddress"/>:<paramref name="remotePort"/>.</summary>
        public static VpnUdpClient Connect(TcpIpStack stack, IPAddress remoteAddress, ushort remotePort)
            => new VpnUdpClient(stack.BindUdp(), remoteAddress, remotePort);

        /// <summary>Sends a datagram to the connected remote endpoint.</summary>
        public void Send(ReadOnlySpan<byte> data) => _socket.SendTo(_remoteAddress, _remotePort, data);

        /// <summary>Receives the next datagram from the connected remote endpoint (others are skipped).</summary>
        public async Task<byte[]> ReceiveAsync(CancellationToken cancellationToken = default)
        {
            while (true)
            {
                UdpReceiveResult result = await _socket.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                if (result.RemoteAddress.Equals(_remoteAddress) && result.RemotePort == _remotePort)
                    return result.Data;
            }
        }
    }
}
