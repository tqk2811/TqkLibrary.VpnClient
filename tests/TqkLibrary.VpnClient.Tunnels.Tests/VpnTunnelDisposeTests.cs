using System.Net;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.Core.Models;
using TqkLibrary.VpnClient.IpStack;
using Xunit;

namespace TqkLibrary.VpnClient.Tunnels.Tests
{
    /// <summary>
    /// The tunnel owns its <see cref="TcpIpStack"/>: disposing the tunnel disposes the stack, and does so BEFORE the
    /// connection underneath goes, so an egress write in flight is cancelled rather than left to fault against a
    /// channel being torn down.
    /// </summary>
    public class VpnTunnelDisposeTests
    {
        [Fact]
        public async Task DisposeAsync_DisposesTheStack_BeforeTheConnection()
        {
            var channel = new PendingChannel();
            var stack = new TcpIpStack(channel, IPAddress.Parse("10.0.0.1"));
            bool cancelledBeforeConnectionDisposed = false;
            var tunnel = new VpnTunnel(new IdleConnection(), stack,
                () => { cancelledBeforeConnectionDisposed = channel.LastToken.IsCancellationRequested; return default; },
                IPAddress.Parse("10.0.0.1"), 1400, "test");

            stack.BindUdp().SendTo(IPAddress.Parse("10.0.0.2"), 9, new byte[] { 1 });
            Assert.Equal(1, channel.Calls);   // the write is in flight (never completes on its own)

            await tunnel.DisposeAsync();

            Assert.True(cancelledBeforeConnectionDisposed, "the stack was not disposed before the connection");
            Assert.Equal(0, stack.EgressFaults);
            // A disposed stack sends nothing more.
            stack.BindUdp().SendTo(IPAddress.Parse("10.0.0.2"), 9, new byte[] { 2 });
            Assert.Equal(1, channel.Calls);
        }

        /// <summary>A write that only ends when cancelled.</summary>
        sealed class PendingChannel : IPacketChannel
        {
            public LinkMedium Medium => LinkMedium.Ip;
            public int Mtu => 1400;
            public int MaxHeaderLength => 0;
            public bool RequiresLinkAddressResolution => false;
            public event Action<ReadOnlyMemory<byte>>? InboundIpPacket { add { } remove { } }
            public int Calls;
            public CancellationToken LastToken;

            public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            {
                Interlocked.Increment(ref Calls);
                LastToken = cancellationToken;
                return new ValueTask(Task.Delay(Timeout.Infinite, cancellationToken));
            }

            public ValueTask DisposeAsync() => default;
        }

        /// <summary>A driver that is never started: the tunnel only subscribes to its state.</summary>
        sealed class IdleConnection : ReconnectingVpnConnection
        {
            public IdleConnection() : base("test", new VpnReconnectOptions { Enabled = false }) { }
            protected override Task EstablishAsync(CancellationToken cancellationToken) => Task.CompletedTask;
            protected override Task CleanupAttemptResourcesAsync() => Task.CompletedTask;
            protected override void StopAttemptLoop() { }
        }
    }
}
