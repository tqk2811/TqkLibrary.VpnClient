using System.Net;
using System.Text;
using System.Threading.Channels;
using TqkLibrary.Vpn.Abstractions.Channels.Enums;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.IpStack.Tcp;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;
using TqkLibrary.Vpn.IpStack.Udp;
using Xunit;

namespace TqkLibrary.Vpn.IpStack.Tests
{
    /// <summary>TCP and UDP running over IPv6 through the userspace stack: handshake + data echo + close, a UDP
    /// round trip, and MSS derived from the link MTU minus the larger IPv6 header.</summary>
    public class Ipv6TcpUdpTests
    {
        static readonly IPAddress ClientIp = IPAddress.Parse("fd00::1");
        static readonly IPAddress ServerIp = IPAddress.Parse("fd00::2");

        [Fact]
        public async Task Tcp_Handshake_DataEcho_AndActiveClose_OverIpv6()
        {
            var link = new LoopbackPair();
            var stack = new TcpIpStack(link.A, ClientIp);
            var server = new PassiveTcpServerV6(link.B, ServerIp);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            TcpConnection connection = await stack.ConnectAsync(ServerIp, 80, cts.Token);

            connection.Send(Encoding.ASCII.GetBytes("ping6"));
            byte[] buffer = new byte[5];
            int offset = 0;
            while (offset < buffer.Length)
            {
                int read = await connection.ReadAsync(buffer, offset, buffer.Length - offset, cts.Token);
                if (read == 0) break;
                offset += read;
            }
            Assert.Equal("ping6", Encoding.ASCII.GetString(buffer, 0, offset));
            Assert.Equal(1, server.AcceptedConnections);

            connection.CloseSend();
            int n = await connection.ReadAsync(buffer, 0, buffer.Length, cts.Token);
            Assert.Equal(0, n);
        }

        [Fact]
        public async Task Udp_RoundTrips_OverIpv6()
        {
            var link = new LoopbackPair();
            var clientStack = new TcpIpStack(link.A, ClientIp);
            var serverStack = new TcpIpStack(link.B, ServerIp);
            UdpConnection server = serverStack.BindUdp(5353);
            UdpConnection client = clientStack.BindUdp();

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            byte[] payload = Encoding.ASCII.GetBytes("udp6-hello");
            client.SendTo(ServerIp, 5353, payload);

            UdpReceiveResult got = await server.ReceiveAsync(cts.Token);
            Assert.Equal(payload, got.Data);
            Assert.Equal(ClientIp, got.RemoteAddress);

            // Reply back to the client's reported endpoint.
            server.SendTo(got.RemoteAddress, got.RemotePort, Encoding.ASCII.GetBytes("udp6-reply"));
            UdpReceiveResult back = await client.ReceiveAsync(cts.Token);
            Assert.Equal("udp6-reply", Encoding.ASCII.GetString(back.Data));
            Assert.Equal(ServerIp, back.RemoteAddress);
        }

        [Fact]
        public void Syn_AdvertisesMss_DerivedFromMtuMinus60()
        {
            var channel = new CaptureChannel(); // MTU 1400 → IPv6 MSS = 1400 − 40 (IPv6) − 20 (TCP) = 1340
            var stack = new TcpIpStack(channel, ClientIp);

            _ = stack.ConnectAsync(ServerIp, 80); // synchronous up to the first await → the SYN is emitted

            byte[] syn = Assert.Single(channel.Written);
            Assert.True(Ipv6.TryGetUpperLayer(syn, out byte proto, out int off));
            Assert.Equal(Ipv6.NextHeaderTcp, proto);
            Assert.Equal((TcpFlags.Syn), TcpSegment.Flags(syn.AsSpan(off)) & TcpFlags.Syn);
            Assert.Equal(1340, TcpSegment.MaxSegmentSize(syn.AsSpan(off)));
        }

        /// <summary>A minimal passive (listen-side) TCP endpoint over IPv6, built directly on the codecs.</summary>
        sealed class PassiveTcpServerV6
        {
            const uint ServerIss = 6000;
            readonly IPacketChannel _channel;
            readonly IPAddress _localIp;
            IPAddress _remoteIp = IPAddress.IPv6Any;
            ushort _localPort, _remotePort;
            uint _sndNxt, _rcvNxt;
            bool _synced;

            public PassiveTcpServerV6(IPacketChannel channel, IPAddress localIp)
            {
                _channel = channel;
                _localIp = localIp;
                _channel.InboundIpPacket += OnInbound;
            }

            public int AcceptedConnections { get; private set; }

            void OnInbound(ReadOnlyMemory<byte> ipPacket)
            {
                ReadOnlySpan<byte> ip = ipPacket.Span;
                if (ip.Length < Ipv6.HeaderLength || Ipv6.Version(ip) != 6) return;
                if (!Ipv6.TryGetUpperLayer(ip, out byte proto, out int off) || proto != Ipv6.NextHeaderTcp) return;

                ReadOnlyMemory<byte> tcp = ipPacket.Slice(off);
                ReadOnlySpan<byte> seg = tcp.Span;
                if (seg.Length < 20) return;

                TcpFlags flags = TcpSegment.Flags(seg);
                uint seq = TcpSegment.Sequence(seg);
                ReadOnlyMemory<byte> payload = TcpSegment.Payload(tcp);
                int len = payload.Length;

                _remoteIp = Ipv6.Source(ip);
                _remotePort = TcpSegment.SourcePort(seg);
                _localPort = TcpSegment.DestinationPort(seg);

                if ((flags & TcpFlags.Syn) != 0)
                {
                    _rcvNxt = seq + 1;
                    _sndNxt = ServerIss;
                    Send(TcpFlags.Syn | TcpFlags.Ack, ReadOnlySpan<byte>.Empty, mss: 1340);
                    _sndNxt += 1;
                    _synced = true;
                    AcceptedConnections++;
                    return;
                }

                if (!_synced) return;

                if (len > 0 && seq == _rcvNxt)
                {
                    _rcvNxt += (uint)len;
                    Send(TcpFlags.Psh | TcpFlags.Ack, payload.Span); // echo (carries the ACK)
                    _sndNxt += (uint)len;
                }

                if ((flags & TcpFlags.Fin) != 0 && seq + (uint)len == _rcvNxt)
                {
                    _rcvNxt += 1;
                    Send(TcpFlags.Fin | TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
                    _sndNxt += 1;
                }
            }

            void Send(TcpFlags flags, ReadOnlySpan<byte> payload, ushort mss = 0)
            {
                byte[] tcp = TcpSegment.Build(_localIp, _remoteIp, _localPort, _remotePort, _sndNxt, _rcvNxt, flags, 65535, payload, mss);
                byte[] ip = Ipv6.Build(_localIp, _remoteIp, Ipv6.NextHeaderTcp, tcp);
                _ = _channel.WriteIpPacketAsync(ip);
            }
        }

        /// <summary>An in-memory IP channel that records outbound packets synchronously (no peer).</summary>
        sealed class CaptureChannel : IPacketChannel
        {
            public LinkMedium Medium => LinkMedium.Ip;
            public int Mtu => 1400;
            public int MaxHeaderLength => 0;
            public bool RequiresLinkAddressResolution => false;
            public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

            public readonly List<byte[]> Written = new();

            public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            {
                Written.Add(ipPacket.ToArray());
                return default;
            }

            public void Inject(byte[] ipPacket) => InboundIpPacket?.Invoke(ipPacket);
            public ValueTask DisposeAsync() => default;
        }

        /// <summary>Two in-memory IP packet channels wired back to back with a serialized async delivery pump.</summary>
        sealed class LoopbackPair
        {
            public LoopbackPair()
            {
                var a = new Chan();
                var b = new Chan();
                a.Peer = b; b.Peer = a;
                A = a; B = b;
            }

            public IPacketChannel A { get; }
            public IPacketChannel B { get; }

            sealed class Chan : IPacketChannel
            {
                readonly Channel<byte[]> _queue = System.Threading.Channels.Channel.CreateUnbounded<byte[]>(
                    new UnboundedChannelOptions { SingleReader = true });

                public Chan() { _ = Task.Run(DrainAsync); }

                public Chan? Peer;
                public LinkMedium Medium => LinkMedium.Ip;
                public int Mtu => 1400;
                public int MaxHeaderLength => 0;
                public bool RequiresLinkAddressResolution => false;
                public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

                public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
                {
                    Peer?._queue.Writer.TryWrite(ipPacket.ToArray());
                    return default;
                }

                async Task DrainAsync()
                {
                    while (await _queue.Reader.WaitToReadAsync().ConfigureAwait(false))
                        while (_queue.Reader.TryRead(out byte[]? packet))
                            InboundIpPacket?.Invoke(packet);
                }

                public ValueTask DisposeAsync() { _queue.Writer.TryComplete(); return default; }
            }
        }
    }
}
