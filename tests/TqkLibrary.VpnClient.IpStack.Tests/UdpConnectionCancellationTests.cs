using System.Net;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.IpStack.Udp;
using Xunit;

namespace TqkLibrary.VpnClient.IpStack.Tests
{
    /// <summary>
    /// Concurrency/cancellation invariants of <see cref="UdpConnection.ReceiveAsync"/> (roadmap Q.3). The receive waiter
    /// is a one-shot <see cref="TaskCompletionSource{T}"/> that a concurrent inbound datagram nulls out of the shared
    /// field; the cancellation registration must therefore key off the local waiter, never the field — otherwise a
    /// datagram landing between publishing the waiter and registering would hand the callback a null and NRE on the
    /// cancelling thread (synchronously, when the token is already cancelled).
    /// </summary>
    public class UdpConnectionCancellationTests
    {
        [Fact]
        public async Task ReceiveAsync_HonorsCancellation_WhenNoDatagramArrives()
        {
            var link = new LoopbackPair();
            var stack = new TcpIpStack(link.A, IPAddress.Parse("10.0.0.1"));
            UdpConnection socket = stack.BindUdp(6001);

            using var cts = new CancellationTokenSource();
            Task<UdpReceiveResult> pending = socket.ReceiveAsync(cts.Token);
            Assert.False(pending.IsCompleted); // nothing queued — it parks on the waiter

            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        }

        [Fact]
        public async Task ReceiveAsync_AlreadyCancelledToken_ThrowsOperationCanceled_NotNullReference()
        {
            var link = new LoopbackPair();
            var stack = new TcpIpStack(link.A, IPAddress.Parse("10.0.0.1"));
            UdpConnection socket = stack.BindUdp(6002);

            using var cts = new CancellationTokenSource();
            cts.Cancel(); // the cancellation registration fires synchronously inside ReceiveAsync

            // The buggy version registered against the (possibly null) field and could NRE here on the inline callback;
            // the fix keys off the local waiter, so this is a clean OperationCanceledException.
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => socket.ReceiveAsync(cts.Token));
        }

        [Fact]
        public async Task ReceiveAsync_DeliveryRacingCancellation_NeverFaultsWithNullReference()
        {
            // Each round either receives the in-flight datagram or is cancelled; under the buggy field-keyed
            // registration a datagram nulling the field just before a synchronous cancel callback would throw an
            // unobserved NRE on the cancelling thread. Stress the interleaving to prove the invariant holds.
            for (int round = 0; round < 200; round++)
            {
                var link = new LoopbackPair();
                var sender = new TcpIpStack(link.A, IPAddress.Parse("10.0.0.1"));
                var receiver = new TcpIpStack(link.B, IPAddress.Parse("10.0.0.2"));
                UdpConnection server = receiver.BindUdp(7000);
                UdpConnection client = sender.BindUdp(7001);

                using var cts = new CancellationTokenSource();
                Task<UdpReceiveResult> recv = server.ReceiveAsync(cts.Token);

                // Fire the datagram and the cancellation as close together as possible.
                client.SendTo(IPAddress.Parse("10.0.0.2"), 7000, new byte[] { (byte)round });
                cts.Cancel();

                try
                {
                    UdpReceiveResult r = await recv;
                    Assert.Single(r.Data); // the datagram won the race — payload intact
                }
                catch (OperationCanceledException)
                {
                    // cancellation won the race — acceptable; the point is it neither hangs nor NREs
                }
            }
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
