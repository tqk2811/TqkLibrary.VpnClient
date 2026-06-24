using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.ZeroTier.Transport;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.ZeroTier.Identity;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl1;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Enums;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl2;
using TqkLibrary.VpnClient.ZeroTier.Vl2.Models;

namespace TqkLibrary.VpnClient.Drivers.ZeroTier.Tests
{
    /// <summary>
    /// An in-memory connected UDP loopback that ties the real <see cref="ZeroTierConnection"/> to an in-process ZeroTier
    /// peer/controller built from the same protocol blocks (the VL1 codec + the VL2 frame/dictionary codecs + the
    /// Ethernet/ARP codecs). Lossless + ordered, each send delivered to the peer on the thread pool. Throwaway test
    /// scaffolding — the library is a client; the node/controller role exists only here. Mirrors the n2n / Nebula driver
    /// loopback harnesses.
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

    /// <summary>An <see cref="IZeroTierTransportFactory"/> that hands back a fixed in-process pipe (self-pumping loopback).</summary>
    sealed class InProcessZeroTierTransportFactory : IZeroTierTransportFactory
    {
        readonly LoopbackUdpLink.Endpoint _endpoint;
        public InProcessZeroTierTransportFactory(LoopbackUdpLink.Endpoint endpoint) => _endpoint = endpoint;

        public Task<ZeroTierTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
            => Task.FromResult(new ZeroTierTransportHandle(_endpoint, _endpoint.SetReceiver, receivePump: null));
    }

    /// <summary>
    /// A throwaway ZeroTier node + controller + gateway peer: it answers HELLO with OK(HELLO) (echoing the timestamp),
    /// answers NETWORK_CONFIG_REQUEST with a config dictionary (one assigned /24 + a COM), and for every inbound
    /// EXT_FRAME it decodes the encapsulated Ethernet frame, answers ARP for the gateway, and echoes inbound IPv4 unicast
    /// frames back (swapping MAC src/dst) — re-wrapping each reply as an EXT_FRAME. Re-implemented from ZeroTier's wire
    /// behaviour; no GPL/BSL source.
    /// </summary>
    sealed class SimulatedZeroTierNode : IDisposable
    {
        readonly LoopbackUdpLink.Endpoint _transport;
        readonly ZeroTierIdentity _self;        // the node/controller identity (has private key)
        readonly ZeroTierIdentity _client;      // the client's public identity
        readonly NetworkId _network;
        readonly IPAddress _assignedIp;
        readonly IPAddress _gateway;
        readonly byte[] _sessionKey;
        readonly Vl1PacketCodec _packetCodec = new();
        readonly HelloMessageCodec _helloCodec = new();
        readonly NetworkConfigCodec _networkConfigCodec = new();
        readonly Vl2ExtFrameCodec _extCodec = new();
        readonly Vl2FrameCodec _frameCodec = new();
        readonly InetAddressCodec _inetCodec = new();
        readonly Random _rng = new(12345);
        readonly MacAddress _gatewayMac = MacAddress.Parse("8e:00:00:00:7e:01");

        public int HelloCount { get; private set; }
        public int NetworkConfigRequestCount { get; private set; }
        public int ExtFrameCount { get; private set; }

        public SimulatedZeroTierNode(LoopbackUdpLink.Endpoint transport, ZeroTierIdentity nodePublic, ZeroTierIdentity clientSecret,
            NetworkId network, IPAddress assignedIp, IPAddress gateway)
        {
            _transport = transport;
            _self = nodePublic;       // the node's identity (address used as VL1 source when sealing replies)
            _client = clientSecret;   // the client's identity (address used as VL1 destination)
            _network = network;
            _assignedIp = assignedIp;
            _gateway = gateway;
            // X25519 is symmetric: agree(clientPriv, nodePub) == agree(nodePriv, clientPub). The harness only holds the
            // node's public key (the KAT identities give the node public-only), so it derives the same session key from
            // the client's private + the node's public — identical to what the real node computes.
            _sessionKey = new Vl1KeyDerivation().DeriveSharedKey(clientSecret.Curve25519Private, nodePublic.Curve25519Public);
            _transport.SetReceiver(OnInbound);
        }

        public MacAddress GatewayMac => _gatewayMac;

        void OnInbound(ReadOnlyMemory<byte> datagram)
        {
            if (!_packetCodec.Open(datagram.Span, _sessionKey, out Vl1Header header, out byte[] payload)) return;
            switch (header.Verb)
            {
                case Vl1Verb.Hello: HandleHello(header, payload); break;
                case Vl1Verb.NetworkConfigRequest: HandleNetworkConfigRequest(); break;
                case Vl1Verb.ExtFrame: HandleExtFrame(payload); break;
                case Vl1Verb.Echo: /* keepalive — silently absorb */ break;
                default: break;
            }
        }

        void HandleHello(Vl1Header header, byte[] payload)
        {
            HelloCount++;
            if (!_helloCodec.TryDecode(payload, out HelloMessage hello)) return;

            // OK(HELLO): inReVerb || inRePacketId || timestampEcho || proto/major/minor/revision || physical InetAddress.
            byte[] physical = _inetCodec.Encode(new InetAddressValue { Address = IPAddress.Parse("198.51.100.7"), Port = 9993 });
            byte[] body = new byte[1 + 8 + 8 + 1 + 1 + 1 + 2 + physical.Length];
            int o = 0;
            body[o++] = (byte)Vl1Verb.Hello;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(o, 8), header.PacketId); o += 8;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(o, 8), hello.Timestamp); o += 8;
            body[o++] = 13; body[o++] = 1; body[o++] = 14;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(o, 2), 0); o += 2;
            physical.CopyTo(body, o);

            SendSealed(Vl1Verb.Ok, body);
        }

        void HandleNetworkConfigRequest()
        {
            NetworkConfigRequestCount++;

            // Build a controller config dictionary: one assigned /24 IPv4 + a (dummy) COM blob + MTU.
            byte[] ipBlob = _inetCodec.Encode(new InetAddressValue { Address = _assignedIp, Port = 24 });
            byte[] com = new byte[1 + 2 + 5 + 64]; com[0] = 1; // version 1, qualifierCount 0
            var dict = new ZeroTierDictionary();
            dict.SetBytes("I", ipBlob);
            dict.SetBytes("C", com);
            dict.SetUInt64("mtu", 2800);
            byte[] dictBytes = dict.Serialize();

            // OK(NETWORK_CONFIG_REQUEST): OK common header then networkId || dictLen || dict.
            byte[] body = new byte[1 + 8 + 8 + 2 + dictBytes.Length];
            int o = 0;
            body[o++] = (byte)Vl1Verb.NetworkConfigRequest;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(o, 8), 0); o += 8; // inRePacketId (unused)
            _network.Write(body.AsSpan(o, 8)); o += 8;
            body[o++] = (byte)(dictBytes.Length >> 8);
            body[o++] = (byte)dictBytes.Length;
            dictBytes.CopyTo(body, o);

            SendSealed(Vl1Verb.Ok, body);
        }

        void HandleExtFrame(byte[] body)
        {
            ExtFrameCount++;
            if (!_extCodec.TryDecode(body, out Vl2ExtFrame ext)) return;

            byte[] frame = BuildEthernetFrame(ext.DestinationMac, ext.SourceMac, ext.EtherType, ext.FrameData);
            byte[]? reply = BuildReply(frame);
            if (reply is null) return;
            SendExtFrame(reply);
        }

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
            return EthernetFrame.Build(senderMac, _gatewayMac, EthernetFrame.EtherTypeArp,
                ArpPacket.BuildReply(_gatewayMac, targetIp, senderMac, senderIp));
        }

        byte[] BuildIpEcho(byte[] frame)
        {
            MacAddress dst = EthernetFrame.Source(frame);   // back to the client
            ReadOnlyMemory<byte> ip = EthernetFrame.Payload(frame);
            return EthernetFrame.Build(dst, _gatewayMac, EthernetFrame.EtherTypeIpv4, ip.Span);
        }

        void SendExtFrame(byte[] ethernetFrame)
        {
            ReadOnlySpan<byte> span = ethernetFrame;
            var ext = new Vl2ExtFrame
            {
                Network = _network,
                Flags = 0,
                DestinationMac = span.Slice(0, 6).ToArray(),
                SourceMac = span.Slice(6, 6).ToArray(),
                EtherType = (ushort)((span[12] << 8) | span[13]),
                FrameData = span.Slice(14).ToArray(),
            };
            SendSealed(Vl1Verb.ExtFrame, _extCodec.Encode(ext));
        }

        void SendSealed(Vl1Verb verb, byte[] body)
        {
            var header = new Vl1Header
            {
                PacketId = unchecked((ulong)_rng.NextInt64()),
                Destination = _client.Address,
                Source = _self.Address,
                Cipher = Vl1CipherSuite.Salsa2012Poly1305,
                Verb = verb,
            };
            byte[] datagram = _packetCodec.Seal(header, _sessionKey, body);
            _ = _transport.SendAsync(datagram);
        }

        static byte[] BuildEthernetFrame(byte[] dst, byte[] src, ushort etherType, byte[] payload)
        {
            byte[] frame = new byte[14 + payload.Length];
            Array.Copy(dst, 0, frame, 0, 6);
            Array.Copy(src, 0, frame, 6, 6);
            frame[12] = (byte)(etherType >> 8);
            frame[13] = (byte)etherType;
            payload.CopyTo(frame, 14);
            return frame;
        }

        public void Dispose() { }
    }
}
