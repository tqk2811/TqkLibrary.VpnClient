using System.Collections.Concurrent;
using System.Net;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.IpStack.Udp;
using Xunit;

namespace TqkLibrary.VpnClient.IpStack.Tests
{
    /// <summary>
    /// Moving a live stack onto the address a re-established link was given.
    /// </summary>
    /// <remarks>
    /// A driver that mends its own link keeps this stack, but the far side leases from a pool and
    /// rarely hands back the same address. A stack left on the old one keeps sourcing packets from
    /// an address the server has never heard of: the tunnel reads as up and carries nothing, with
    /// no fault reported anywhere. These pin the move itself — the source address that goes on the
    /// wire afterwards, and that nothing is left over from the session before it.
    /// </remarks>
    public class TcpIpStackRebindTests
    {
        static readonly IPAddress First = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress Second = IPAddress.Parse("10.9.9.9");
        static readonly IPAddress Peer = IPAddress.Parse("10.0.0.2");

        [Fact]
        public void AfterRebind_PacketsLeaveFromTheNewAddress()
        {
            var channel = new CapturingChannel();
            var stack = new TcpIpStack(channel, First);

            UdpConnection before = stack.BindUdp();
            before.SendTo(Peer, 53, new byte[] { 1, 2, 3 });
            Assert.Equal(First, SourceOf(channel.Take()));

            stack.Rebind(Second, null);

            UdpConnection after = stack.BindUdp();
            after.SendTo(Peer, 53, new byte[] { 1, 2, 3 });
            Assert.Equal(Second, SourceOf(channel.Take()));
        }

        [Fact]
        public void RebindingToTheSameAddress_ChangesNothing()
        {
            var channel = new CapturingChannel();
            var stack = new TcpIpStack(channel, First);

            UdpConnection socket = stack.BindUdp();
            stack.Rebind(First, null);

            // The socket survived, so the port it holds was not handed back to the pool: a tunnel
            // that reconnected onto the very same lease has nothing to tear down.
            socket.SendTo(Peer, 53, new byte[] { 1 });
            Assert.Equal(First, SourceOf(channel.Take()));
        }

        [Fact]
        public void Rebind_RefusesAnEmptyAddressing()
        {
            var stack = new TcpIpStack(new CapturingChannel(), First);

            Assert.Throws<ArgumentException>(() => stack.Rebind(null, null));
        }

        [Fact]
        public void Rebind_RefusesAnAddressOfTheWrongFamily()
        {
            var stack = new TcpIpStack(new CapturingChannel(), First);

            Assert.Throws<ArgumentException>(() => stack.Rebind(IPAddress.IPv6Loopback, null));
        }

        [Fact]
        public async Task AfterRebind_AConnectionFromTheOldSessionIsFinished()
        {
            // Never answered, so it sits in SYN-SENT — the state a connection is in when the
            // session under it dies. Rebind must end it instead of leaving the caller to a retry
            // timer measured in minutes.
            var channel = new CapturingChannel();
            var stack = new TcpIpStack(channel, First);

            Task<Tcp.TcpConnection> connecting = stack.ConnectAsync(Peer, 80);
            await WaitForAnOutboundPacketAsync(channel);

            stack.Rebind(Second, null);

            await Assert.ThrowsAnyAsync<Exception>(() => connecting);
        }

        static IPAddress SourceOf(byte[] ipPacket) => new IPAddress(ipPacket.Skip(12).Take(4).ToArray());

        static async Task WaitForAnOutboundPacketAsync(CapturingChannel channel)
        {
            for (int i = 0; i < 100 && channel.Count == 0; i++) await Task.Delay(10);
            Assert.True(channel.Count > 0, "the stack sent nothing");
        }

        /// <summary>A channel that only records what the stack writes; nothing ever answers.</summary>
        sealed class CapturingChannel : IPacketChannel
        {
            readonly ConcurrentQueue<byte[]> _written = new ConcurrentQueue<byte[]>();

            public LinkMedium Medium => LinkMedium.Ip;
            public int Mtu => 1400;
            public int MaxHeaderLength => 0;
            public bool RequiresLinkAddressResolution => false;
            public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

            public int Count => _written.Count;

            public byte[] Take()
            {
                Assert.True(_written.TryDequeue(out byte[]? packet), "the stack sent nothing");
                return packet!;
            }

            public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            {
                _written.Enqueue(ipPacket.ToArray());
                _ = InboundIpPacket;   // never raised here; declared to satisfy the interface
                return default;
            }

            public ValueTask DisposeAsync() => default;
        }
    }
}
