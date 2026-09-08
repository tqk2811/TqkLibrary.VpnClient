using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.IpStack.Udp;
using Xunit;

namespace TqkLibrary.VpnClient.IpStack.Tests
{
    /// <summary>
    /// Which local port the stack hands a new flow.
    /// </summary>
    /// <remarks>
    /// The counter used to be an int cast to ushort, starting at 49152, shared by TCP and UDP. After
    /// 16 384 flows the cast wrapped to zero, and the stack began handing out port 0, then 1, and on
    /// through the well-known ports — then round again onto ports still in use. A caller that opens
    /// one short-lived flow per operation reaches that inside a single session: the in-tunnel DNS
    /// resolver bound a socket per query, up to twelve per name.
    /// </remarks>
    public class EphemeralPortAllocationTests
    {
        static readonly IPAddress Local = IPAddress.Parse("10.7.0.2");

        [Fact]
        public void Every_port_handed_out_stays_inside_the_ephemeral_range()
        {
            using var channel = new SilentChannel();
            var stack = new TcpIpStack(channel, Local);

            // Comfortably past the 16 384 the old counter managed before it left the range.
            for (int i = 0; i < 20_000; i++)
            {
                UdpConnection socket = stack.BindUdp();
                Assert.InRange(socket.LocalPort, (ushort)49152, (ushort)65535);
                stack.UnbindUdp(socket.LocalPort);
            }
        }

        [Fact]
        public void A_port_still_in_use_is_never_handed_out_again()
        {
            using var channel = new SilentChannel();
            var stack = new TcpIpStack(channel, Local);

            // Held, not released: the whole range is walked several times over, so every allocation
            // after the first pass lands on a port one of these already owns.
            var held = new List<UdpConnection>();
            var seen = new HashSet<ushort>();
            try
            {
                for (int i = 0; i < 5_000; i++)
                {
                    UdpConnection socket = stack.BindUdp();
                    Assert.True(seen.Add(socket.LocalPort), $"port {socket.LocalPort} was handed out twice");
                    held.Add(socket);
                }
            }
            finally
            {
                foreach (UdpConnection socket in held) stack.UnbindUdp(socket.LocalPort);
            }
        }

        [Fact]
        public void A_released_port_comes_back_once_the_range_has_been_walked()
        {
            using var channel = new SilentChannel();
            var stack = new TcpIpStack(channel, Local);

            UdpConnection first = stack.BindUdp();
            ushort released = first.LocalPort;
            stack.UnbindUdp(released);

            bool seenAgain = false;
            for (int i = 0; i < 16_384 + 8 && !seenAgain; i++)
            {
                UdpConnection socket = stack.BindUdp();
                seenAgain = socket.LocalPort == released;
                stack.UnbindUdp(socket.LocalPort);
            }

            // Skipping ports in use must not mean leaking them: a port whose socket is gone has to
            // become available again, or a long-lived tunnel runs out.
            Assert.True(seenAgain, "a released port never came back round");
        }

        /// <summary>A channel that accepts everything written to it and never delivers anything.</summary>
        sealed class SilentChannel : IPacketChannel, IDisposable
        {
            public LinkMedium Medium => LinkMedium.Ip;
            public int Mtu => 1400;
            public int MaxHeaderLength => 0;
            public bool RequiresLinkAddressResolution => false;

            public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

            public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
                => default;

            public void Dispose() => InboundIpPacket = null;
            public ValueTask DisposeAsync() => default;
        }
    }
}
