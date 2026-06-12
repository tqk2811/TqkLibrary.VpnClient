using System.Net;
using System.Net.Sockets;
using TqkLibrary.Vpn.Ipsec.Nat.Enums;

namespace TqkLibrary.Vpn.Ipsec.Nat
{
    /// <summary>
    /// A UDP channel for L2TP/IPsec that multiplexes IKE and ESP toward one gateway (RFC 3948). It binds an
    /// ephemeral local port (never 500/4500) so it does not collide with the OS IKE service and so the gateway
    /// sees a "NATed" source — which is what pushes it onto UDP/4500 with ESP encapsulation.
    /// Send/receive add and strip the Non-ESP Marker according to the current target port.
    /// </summary>
    public sealed class NatTraversalChannel : IAsyncDisposable
    {
        readonly UdpClient _client;
        readonly IPAddress _remoteAddress;
        IPEndPoint _remote;

        /// <summary>Creates the channel toward <paramref name="remoteAddress"/>, initially targeting the IKE port.</summary>
        public NatTraversalChannel(IPAddress remoteAddress, int remotePort = NatTraversal.IkePort, int localPort = 0)
        {
            _remoteAddress = remoteAddress;
            _remote = new IPEndPoint(remoteAddress, remotePort);
            _client = new UdpClient(localPort);
        }

        /// <summary>The bound local UDP port.</summary>
        public int LocalPort => ((IPEndPoint)_client.Client.LocalEndPoint!).Port;

        /// <summary>The port currently targeted (500 before NAT-T, 4500 after).</summary>
        public int RemotePort => _remote.Port;

        /// <summary>Switches the target to UDP/4500 after NAT has been detected in IKE_SA_INIT.</summary>
        public void SwitchToNatTPort() => _remote = new IPEndPoint(_remoteAddress, NatTraversal.NatTPort);

        /// <summary>Sends an IKE message, prefixing the Non-ESP Marker when the target is port 4500.</summary>
        public Task SendIkeAsync(ReadOnlyMemory<byte> ikeMessage)
        {
            byte[] datagram = _remote.Port == NatTraversal.NatTPort
                ? NatTraversal.WrapIke(ikeMessage.Span)
                : ikeMessage.ToArray();
            return _client.SendAsync(datagram, datagram.Length, _remote);
        }

        /// <summary>Sends a UDP-encapsulated ESP packet (no marker; the SPI is its own first four bytes).</summary>
        public Task SendEspAsync(ReadOnlyMemory<byte> espPacket)
        {
            byte[] datagram = espPacket.ToArray();
            return _client.SendAsync(datagram, datagram.Length, _remote);
        }

        /// <summary>
        /// Receives one datagram and classifies it. On port 500 the payload is always an IKE message; on 4500 the
        /// Non-ESP Marker decides, and the marker is stripped from IKE payloads before returning them.
        /// </summary>
        public async Task<(NatTPacketKind Kind, byte[] Payload)> ReceiveAsync(CancellationToken cancellationToken = default)
        {
#if NET6_0_OR_GREATER
            UdpReceiveResult result = await _client.ReceiveAsync(cancellationToken).ConfigureAwait(false);
#else
            cancellationToken.ThrowIfCancellationRequested();
            UdpReceiveResult result = await _client.ReceiveAsync().ConfigureAwait(false);
#endif
            byte[] data = result.Buffer;
            if (_remote.Port == NatTraversal.IkePort)
                return (data.Length >= 28 ? NatTPacketKind.Ike : NatTPacketKind.Invalid, data);

            NatTPacketKind kind = NatTraversal.Classify(data);
            byte[] payload = kind == NatTPacketKind.Ike ? NatTraversal.UnwrapIke(data) : data;
            return (kind, payload);
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            _client.Dispose();
            return default;
        }
    }
}
