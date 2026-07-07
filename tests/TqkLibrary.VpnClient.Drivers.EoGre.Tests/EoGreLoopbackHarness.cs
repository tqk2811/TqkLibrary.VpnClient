using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.EoGre;
using TqkLibrary.VpnClient.Drivers.EoGre.Transport;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.EoGre.Tests
{
    /// <summary>
    /// An in-memory connected UDP loopback that ties the real <see cref="EoGreConnection"/> to an in-process peer built
    /// from the same protocol blocks (<see cref="EoGreCodec"/> + the Ethernet/ARP codecs). Lossless + ordered, each send
    /// delivered to the peer on the thread pool. Throwaway test scaffolding (no sockets). Mirrors the Geneve driver's
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

    /// <summary>An <see cref="IEoGreTransportFactory"/> that hands back a fixed in-process pipe (self-pumping loopback).</summary>
    sealed class InProcessEoGreTransportFactory : IEoGreTransportFactory
    {
        readonly LoopbackUdpLink.Endpoint _endpoint;
        public InProcessEoGreTransportFactory(LoopbackUdpLink.Endpoint endpoint) => _endpoint = endpoint;

        public Task<EoGreTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
            => Task.FromResult(new EoGreTransportHandle(_endpoint, _endpoint.SetReceiver, receivePump: null));
    }

    /// <summary>
    /// A throwaway EoGRE / NVGRE peer + gateway: for every inbound GRE-in-UDP datagram it decodes the encapsulated Ethernet
    /// frame, answers ARP for the gateway, and echoes inbound IPv4 unicast frames back (swapping MAC src/dst) — re-wrapping
    /// each reply as a GRE datagram (protocol type 0x6558, same VSID/FlowID) via the reused codec. Pure RFC 8086/7637
    /// behaviour; no external source.
    /// </summary>
    sealed class SimulatedEoGrePeer : IDisposable
    {
        readonly LoopbackUdpLink.Endpoint _transport;
        readonly uint? _vsid;
        readonly byte _flowId;
        readonly MacAddress _gatewayMac;

        public int DatagramCount { get; private set; }
        MacAddress? _clientMac;

        public SimulatedEoGrePeer(LoopbackUdpLink.Endpoint transport, uint? vsid, byte flowId = 0)
        {
            _transport = transport;
            _vsid = vsid;
            _flowId = flowId;
            _gatewayMac = MacAddress.Parse("5e:00:00:00:7e:01");
            _transport.SetReceiver(OnInbound);
        }

        /// <summary>The gateway MAC the peer answers ARP with (the next-hop the client resolves before echoing).</summary>
        public MacAddress GatewayMac => _gatewayMac;

        void OnInbound(ReadOnlyMemory<byte> datagram)
        {
            if (!EoGreCodec.TryDecodeEoGre(datagram.Span, out ushort protocolType, out ReadOnlyMemory<byte> frameMem, out uint? key, out _)) return;
            if (protocolType != EoGreCodec.ProtocolTypeTransparentEthernet) return;
            if (_vsid.HasValue)
            {
                if (!key.HasValue) return;
                EoGreCodec.UnpackKey(key.Value, out uint vsid, out _);
                if (vsid != _vsid.Value) return;
            }
            DatagramCount++;

            byte[] frame = frameMem.ToArray();
            _clientMac ??= EthernetFrame.Source(frame);

            byte[]? reply = BuildReply(frame);
            if (reply is null) return;
            _ = _transport.SendAsync(EoGreCodec.EncodeEoGre(reply, _vsid, _flowId));
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
