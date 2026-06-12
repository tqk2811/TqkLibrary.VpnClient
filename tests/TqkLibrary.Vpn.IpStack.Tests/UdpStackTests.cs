using System.Net;
using TqkLibrary.Vpn.Abstractions.Channels.Enums;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.IpStack;
using TqkLibrary.Vpn.IpStack.Udp;
using TqkLibrary.Vpn.Sockets;
using Xunit;

namespace TqkLibrary.Vpn.IpStack.Tests
{
    public class UdpStackTests
    {
        [Fact]
        public void UdpDatagram_RoundTrips_WithChecksum()
        {
            IPAddress src = IPAddress.Parse("10.0.0.1"), dst = IPAddress.Parse("10.0.0.2");
            byte[] payload = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01 };

            byte[] datagram = UdpDatagram.Build(src, dst, 1234, 53, payload);

            Assert.Equal(1234, UdpDatagram.SourcePort(datagram));
            Assert.Equal(53, UdpDatagram.DestinationPort(datagram));
            Assert.Equal(payload, UdpDatagram.Payload(datagram).ToArray());
            Assert.NotEqual(0, (datagram[6] << 8) | datagram[7]); // checksum present
        }

        [Fact]
        public async Task VpnUdpClient_EchoesThroughTwoStacks()
        {
            var link = new LoopbackPair();
            IPAddress ipA = IPAddress.Parse("10.0.0.1"), ipB = IPAddress.Parse("10.0.0.2");
            var stackA = new TcpIpStack(link.A, ipA);
            var stackB = new TcpIpStack(link.B, ipB);

            UdpConnection server = stackB.BindUdp(5353);
            var serverDone = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _ = Task.Run(async () =>
            {
                UdpReceiveResult request = await server.ReceiveAsync();
                server.SendTo(request.RemoteAddress, request.RemotePort,
                    System.Text.Encoding.ASCII.GetBytes("pong:" + System.Text.Encoding.ASCII.GetString(request.Data)));
                serverDone.TrySetResult(true);
            });

            VpnUdpClient client = VpnUdpClient.Connect(stackA, ipB, 5353);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            client.Send(System.Text.Encoding.ASCII.GetBytes("ping"));
            byte[] reply = await client.ReceiveAsync(cts.Token);

            Assert.Equal("pong:ping", System.Text.Encoding.ASCII.GetString(reply));
        }

        /// <summary>Two in-memory IP packet channels wired back to back (A writes → B's inbound, and vice versa).</summary>
        sealed class LoopbackPair
        {
            public LoopbackPair()
            {
                A = new Channel();
                B = new Channel();
                ((Channel)A).Peer = (Channel)B;
                ((Channel)B).Peer = (Channel)A;
            }

            public IPacketChannel A { get; }
            public IPacketChannel B { get; }

            sealed class Channel : IPacketChannel
            {
                public Channel? Peer;
                public LinkMedium Medium => LinkMedium.Ip;
                public int Mtu => 1400;
                public int MaxHeaderLength => 0;
                public bool RequiresLinkAddressResolution => false;
                public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

                public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
                {
                    byte[] copy = ipPacket.ToArray();
                    Channel? peer = Peer;
                    _ = Task.Run(() => peer?.InboundIpPacket?.Invoke(copy));
                    return default;
                }

                public ValueTask DisposeAsync() => default;
            }
        }
    }
}
