using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.VxlanGpe;
using TqkLibrary.VpnClient.Drivers.VxlanGpe.Transport;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.VxlanGpe.Tests
{
    /// <summary>
    /// An in-memory connected UDP loopback that ties the real <see cref="VxlanGpeConnection"/> to an in-process peer built
    /// from the same protocol blocks (<see cref="VxlanGpeHeader"/> + the Ethernet/ARP codecs). Lossless + ordered, each send
    /// delivered to the peer on the thread pool. Throwaway test scaffolding (no sockets). Mirrors the VXLAN driver's
    /// loopback harness.
    /// </summary>
    sealed class LoopbackUdpLink
    {
        readonly Endpoint _client = new();
        readonly Endpoint _server = new();

        public LoopbackUdpLink() { _client.Peer = _server; _server.Peer = _client; }

        public Endpoint Client => _client;
        public Endpoint Server => _server;

        public sealed class Endpoint : IDatagramTransport
        {
            public Endpoint? Peer;
            readonly object _lock = new();
            Task _tail = Task.CompletedTask;
            Action<ReadOnlyMemory<byte>>? _receiver;

            public void SetReceiver(Action<ReadOnlyMemory<byte>> receiver) => _receiver = receiver;

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
            {
                byte[] copy = datagram.ToArray();
                Endpoint? peer = Peer;
                if (peer != null)
                    lock (peer._lock)
                        peer._tail = peer._tail.ContinueWith(_ => peer._receiver?.Invoke(copy), TaskScheduler.Default);
                return default;
            }

            public ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
                => throw new NotSupportedException("The loopback link self-pumps via the registered receiver.");

            public ValueTask DisposeAsync() => default;
        }
    }

    /// <summary>An <see cref="IVxlanGpeTransportFactory"/> that hands back a fixed in-process pipe (self-pumping loopback).</summary>
    sealed class InProcessVxlanGpeTransportFactory : IVxlanGpeTransportFactory
    {
        readonly LoopbackUdpLink.Endpoint _endpoint;
        public InProcessVxlanGpeTransportFactory(LoopbackUdpLink.Endpoint endpoint) => _endpoint = endpoint;

        public Task<VxlanGpeTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
            => Task.FromResult(new VxlanGpeTransportHandle(_endpoint, _endpoint.SetReceiver, receivePump: null));
    }

    /// <summary>
    /// A throwaway VXLAN-GPE peer + gateway: for every inbound VXLAN-GPE datagram (Next Protocol Ethernet) it decodes the
    /// encapsulated Ethernet frame, answers ARP for the gateway, and echoes inbound IPv4 unicast frames back (swapping MAC
    /// src/dst) — re-wrapping each reply as a VXLAN-GPE datagram under the same VNI + Ethernet Next Protocol. Pure
    /// draft-ietf-nvo3-vxlan-gpe behaviour; no external source.
    /// </summary>
    sealed class SimulatedVxlanGpePeer : IDisposable
    {
        readonly LoopbackUdpLink.Endpoint _transport;
        readonly uint _vni;
        readonly MacAddress _gatewayMac;

        public int DatagramCount { get; private set; }
        MacAddress? _clientMac;

        public SimulatedVxlanGpePeer(LoopbackUdpLink.Endpoint transport, uint vni)
        {
            _transport = transport;
            _vni = vni;
            _gatewayMac = MacAddress.Parse("5e:00:00:00:7e:01");
            _transport.SetReceiver(OnInbound);
        }

        /// <summary>The gateway MAC the peer answers ARP with (the next-hop the client resolves before echoing).</summary>
        public MacAddress GatewayMac => _gatewayMac;

        void OnInbound(ReadOnlyMemory<byte> datagram)
        {
            if (!VxlanGpeHeader.TryDecodeVxlanGpe(datagram.Span, out uint vni, out byte nextProtocol, out ReadOnlyMemory<byte> frameMem)) return;
            if (vni != _vni) return;
            if (nextProtocol != VxlanGpeHeader.NextProtocolEthernet) return;
            DatagramCount++;

            byte[] frame = frameMem.ToArray();
            _clientMac ??= EthernetFrame.Source(frame);

            byte[]? reply = BuildReply(frame);
            if (reply is null) return;
            _ = _transport.SendAsync(VxlanGpeHeader.EncodeVxlanGpe(_vni, VxlanGpeHeader.NextProtocolEthernet, reply));
        }

        // Returns the frame to send back for an inbound frame (ARP reply / IP echo), or null to drop.
        byte[]? BuildReply(byte[] frame)
        {
            if (frame.Length < EthernetFrame.HeaderLength) return null;
            ushort etherType = EthernetFrame.EtherType(frame);
            if (etherType == EthernetFrame.EtherTypeArp) return BuildArpReply(frame);
            if (etherType == EthernetFrame.EtherTypeIpv4) return BuildIpEcho(frame);
            return null;
        }

        byte[]? BuildArpReply(byte[] frame)
        {
            ReadOnlySpan<byte> arp = EthernetFrame.Payload(frame).Span;
            if (!ArpPacket.IsIpv4OverEthernet(arp) || ArpPacket.Operation(arp) != ArpPacket.OperationRequest) return null;

            MacAddress senderMac = ArpPacket.SenderMac(arp);
            IPAddress senderIp = ArpPacket.SenderIp(arp);
            IPAddress targetIp = ArpPacket.TargetIp(arp);

            // Answer for any in-subnet target with the gateway MAC (proxy-ARP for the gateway/world).
            return EthernetFrame.Build(senderMac, _gatewayMac, EthernetFrame.EtherTypeArp,
                ArpPacket.BuildReply(_gatewayMac, targetIp, senderMac, senderIp));
        }

        // Echo an inbound IPv4 unicast frame back to the client (swap the MACs, keep the payload byte-exact).
        byte[] BuildIpEcho(byte[] frame)
        {
            MacAddress dst = EthernetFrame.Source(frame);   // back to the client
            ReadOnlyMemory<byte> ip = EthernetFrame.Payload(frame);
            return EthernetFrame.Build(dst, _gatewayMac, EthernetFrame.EtherTypeIpv4, ip.Span);
        }

        public void Dispose() { }
    }
}
