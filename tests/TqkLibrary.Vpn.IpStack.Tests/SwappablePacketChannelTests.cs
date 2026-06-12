using System.Net;
using System.Text;
using TqkLibrary.Vpn.Abstractions.Channels;
using TqkLibrary.Vpn.Abstractions.Channels.Enums;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.IpStack.Udp;
using TqkLibrary.Vpn.Sockets;
using Xunit;

namespace TqkLibrary.Vpn.IpStack.Tests
{
    public class SwappablePacketChannelTests
    {
        [Fact]
        public async Task Facade_ForwardsToCurrentInner_AndDetachesThePrevious()
        {
            var facade = new SwappablePacketChannel();
            var a = new FakeChannel();
            var b = new FakeChannel();

            int received = 0;
            facade.InboundIpPacket += _ => received++;

            // No inner attached yet: a write is dropped, never throws.
            await facade.WriteIpPacketAsync(new byte[] { 1 });

            facade.SetInner(a);
            a.RaiseInbound(new byte[] { 0xAA });
            Assert.Equal(1, received);                       // inbound forwarded synchronously
            await facade.WriteIpPacketAsync(new byte[] { 0x01 });
            Assert.Single(a.Writes);                         // write reaches the current inner

            facade.SetInner(b);
            a.RaiseInbound(new byte[] { 0xBB });
            Assert.Equal(1, received);                       // the previous inner is detached
            b.RaiseInbound(new byte[] { 0xCC });
            Assert.Equal(2, received);                       // the new inner is attached
            await facade.WriteIpPacketAsync(new byte[] { 0x02 });
            Assert.Single(b.Writes);                         // writes now reach the new inner...
            Assert.Single(a.Writes);                         // ...and no longer the old one
        }

        [Fact]
        public void Facade_PinsLinkMetadataFromTheFirstInner()
        {
            var facade = new SwappablePacketChannel();
            facade.SetInner(new FakeChannel { Medium = LinkMedium.Ip, Mtu = 1300, MaxHeaderLength = 0 });
            Assert.Equal(1300, facade.Mtu);

            facade.SetInner(new FakeChannel { Mtu = 9000 });
            Assert.Equal(1300, facade.Mtu); // unchanged across a swap
        }

        [Fact]
        public async Task TcpIpStack_SurvivesAChannelSwap_SameUdpConnectionKeepsWorking()
        {
            var hub = new Hub();
            var facade = new SwappablePacketChannel();
            facade.SetInner(hub.ClientA);

            IPAddress ipClient = IPAddress.Parse("10.0.0.1"), ipServer = IPAddress.Parse("10.0.0.2");
            var clientStack = new TcpIpStack(facade, ipClient);
            var serverStack = new TcpIpStack(hub.Server, ipServer);

            UdpConnection echo = serverStack.BindUdp(5353);
            _ = Task.Run(async () =>
            {
                for (int i = 0; i < 2; i++)
                {
                    UdpReceiveResult r = await echo.ReceiveAsync();
                    echo.SendTo(r.RemoteAddress, r.RemotePort, Encoding.ASCII.GetBytes("pong:" + Encoding.ASCII.GetString(r.Data)));
                }
            });

            VpnUdpClient client = VpnUdpClient.Connect(clientStack, ipServer, 5353);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            client.Send(Encoding.ASCII.GetBytes("ping1"));
            Assert.Equal("pong:ping1", Encoding.ASCII.GetString(await client.ReceiveAsync(cts.Token)));

            // "Reconnect": hot-swap the facade's inner to a brand-new path to the same server (same client IP).
            facade.SetInner(hub.ClientB);

            client.Send(Encoding.ASCII.GetBytes("ping2"));
            Assert.Equal("pong:ping2", Encoding.ASCII.GetString(await client.ReceiveAsync(cts.Token)));
        }

        sealed class FakeChannel : IPacketChannel
        {
            public List<byte[]> Writes { get; } = new();
            public LinkMedium Medium { get; set; } = LinkMedium.Ip;
            public int Mtu { get; set; } = 1400;
            public int MaxHeaderLength { get; set; }
            public bool RequiresLinkAddressResolution { get; set; }
            public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

            public void RaiseInbound(byte[] packet) => InboundIpPacket?.Invoke(packet);

            public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            {
                Writes.Add(ipPacket.ToArray());
                return default;
            }

            public ValueTask DisposeAsync() => default;
        }

        /// <summary>Two client-side channels both wired to one server channel; the server broadcasts to both, but only
        /// the facade's currently-attached inner has a live subscriber, so a swap reroutes traffic transparently.</summary>
        sealed class Hub
        {
            public Hub()
            {
                ClientA = new HubChannel();
                ClientB = new HubChannel();
                Server = new HubChannel();
                ClientA.Target = Server;
                ClientB.Target = Server;
                Server.Broadcast = new[] { ClientA, ClientB };
            }

            public HubChannel ClientA { get; }
            public HubChannel ClientB { get; }
            public HubChannel Server { get; }
        }

        sealed class HubChannel : IPacketChannel
        {
            public HubChannel? Target;
            public HubChannel[]? Broadcast;

            public LinkMedium Medium => LinkMedium.Ip;
            public int Mtu => 1400;
            public int MaxHeaderLength => 0;
            public bool RequiresLinkAddressResolution => false;
            public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

            public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            {
                byte[] copy = ipPacket.ToArray();
                if (Target != null) { HubChannel t = Target; _ = Task.Run(() => t.InboundIpPacket?.Invoke(copy)); }
                if (Broadcast != null)
                    foreach (HubChannel c in Broadcast) { HubChannel cc = c; _ = Task.Run(() => cc.InboundIpPacket?.Invoke(copy)); }
                return default;
            }

            public ValueTask DisposeAsync() => default;
        }
    }
}
