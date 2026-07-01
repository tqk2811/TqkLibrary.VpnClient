using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.Drivers.Core.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Core.Tests
{
    /// <summary>
    /// Exercises the shared <see cref="ReconnectingVpnConnection"/> supervisor (roadmap F.6) in isolation
    /// through a tiny fake driver: it must run the initial establish, arm the reconnect loop after a link loss, retry
    /// with the configured policy (max-attempts / disabled / backoff), raise <c>StateChanged</c> and the reconnected
    /// hook, and tear down cleanly. This is the contract the WireGuard / OpenConnect drivers now inherit instead of
    /// duplicating.
    /// </summary>
    public class ReconnectingVpnConnectionTests
    {
        // A no-op channel so the facade has something to bind (the test never sends packets through it).
        sealed class DummyChannel : IPacketChannel
        {
            public LinkMedium Medium => LinkMedium.Ip;
            public int Mtu => 1400;
            public int MaxHeaderLength => 0;
            public bool RequiresLinkAddressResolution => false;
            public event Action<ReadOnlyMemory<byte>>? InboundIpPacket { add { } remove { } }
            public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken ct = default) => default;
            public ValueTask DisposeAsync() => default;
        }

        sealed class TestConnection : ReconnectingVpnConnection, IAsyncDisposable
        {
            readonly Func<int, bool> _establishSucceeds; // (attemptOrdinal) => succeed?
            public int EstablishCount;
            public int CleanupCount;
            public int ReconnectedCount;

            public TestConnection(VpnReconnectOptions options, Func<int, bool> establishSucceeds)
                : base("test", options, clock: () => 0)
            {
                _establishSucceeds = establishSucceeds;
            }

            protected override Task EstablishAsync(CancellationToken cancellationToken)
            {
                int ordinal = Interlocked.Increment(ref EstablishCount);
                cancellationToken.ThrowIfCancellationRequested();
                if (!_establishSucceeds(ordinal))
                    throw new InvalidOperationException($"establish #{ordinal} failed (test)");
                Facade.SetInner(new DummyChannel());
                MarkConnected();
                return Task.CompletedTask;
            }

            protected override Task CleanupAttemptResourcesAsync()
            {
                Interlocked.Increment(ref CleanupCount);
                return Task.CompletedTask;
            }

            protected override void StopAttemptLoop() { }

            protected override void OnReconnected() => Interlocked.Increment(ref ReconnectedCount);

            // Expose the protected hooks the real drivers call.
            public Task ConnectAsync(CancellationToken ct = default) => ConnectCoreAsync(ct);
            public void Drop(string reason) => OnLinkLost(reason);

            public async ValueTask DisposeAsync()
            {
                await DisconnectAsync().ConfigureAwait(false);
                await DisposeCoreAsync().ConfigureAwait(false);
            }
        }

        static VpnReconnectOptions FastOptions(bool enabled = true, int maxAttempts = 0) => new VpnReconnectOptions
        {
            Enabled = enabled,
            MaxAttempts = maxAttempts,
            InitialBackoff = TimeSpan.FromMilliseconds(5),
            MaxBackoff = TimeSpan.FromMilliseconds(20),
            JitterFraction = 0, // deterministic timing in tests
        };

        static async Task WaitUntilAsync(Func<bool> condition, CancellationToken ct)
        {
            while (!condition())
            {
                ct.ThrowIfCancellationRequested();
                await Task.Delay(10, ct);
            }
        }

        [Fact]
        public async Task Connect_RunsEstablishOnce_AndGoesConnected_WithStateEvents()
        {
            var states = new List<VpnConnectionState>();
            await using var conn = new TestConnection(FastOptions(), _ => true);
            conn.StateChanged += s => { lock (states) states.Add(s); };

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await conn.ConnectAsync(cts.Token);

            Assert.Equal(VpnConnectionState.Connected, conn.State);
            Assert.Equal(1, conn.EstablishCount);
            lock (states)
            {
                Assert.Contains(VpnConnectionState.Connecting, states);
                Assert.Contains(VpnConnectionState.Connected, states);
            }
        }

        [Fact]
        public async Task FirstEstablishFails_ConnectThrows_NoReconnectArmed()
        {
            // The very first connect failing must surface to the caller (reconnect only arms after a success).
            await using var conn = new TestConnection(FastOptions(), _ => false);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            await Assert.ThrowsAsync<InvalidOperationException>(() => conn.ConnectAsync(cts.Token));
            Assert.Equal(1, conn.EstablishCount); // no retry on the initial connect
            Assert.Equal(VpnConnectionState.Connecting, conn.State);
        }

        [Fact]
        public async Task LinkLoss_ArmsSupervisor_Reconnects_AndRaisesReconnected()
        {
            // First connect succeeds; the second establish (the reconnect) succeeds too.
            await using var conn = new TestConnection(FastOptions(), _ => true);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await conn.ConnectAsync(cts.Token);
            Assert.Equal(VpnConnectionState.Connected, conn.State);

            conn.Drop("test-induced link loss");

            await WaitUntilAsync(() => conn.ReconnectedCount > 0, cts.Token);
            Assert.Equal(VpnConnectionState.Connected, conn.State);
            Assert.Equal(2, conn.EstablishCount); // initial + one reconnect
            Assert.Equal(1, conn.ReconnectedCount);
        }

        [Fact]
        public async Task LinkLoss_WithReconnectDisabled_GoesDisconnected_NoRetry()
        {
            await using var conn = new TestConnection(FastOptions(enabled: false), _ => true);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await conn.ConnectAsync(cts.Token);

            conn.Drop("link loss with reconnect off");

            await WaitUntilAsync(() => conn.State == VpnConnectionState.Disconnected, cts.Token);
            Assert.Equal(VpnConnectionState.Disconnected, conn.State);
            Assert.Equal(1, conn.EstablishCount); // no reconnect attempted
            Assert.Equal(0, conn.ReconnectedCount);
        }

        [Fact]
        public async Task ReconnectAttempts_RespectMaxAttempts_ThenGiveUp()
        {
            // First connect (ordinal 1) succeeds; every reconnect attempt fails. With MaxAttempts=3 the supervisor
            // tries three times then gives up and goes Disconnected.
            await using var conn = new TestConnection(FastOptions(maxAttempts: 3), ordinal => ordinal == 1);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await conn.ConnectAsync(cts.Token);

            conn.Drop("link loss; all reconnects will fail");

            await WaitUntilAsync(() => conn.State == VpnConnectionState.Disconnected, cts.Token);
            Assert.Equal(VpnConnectionState.Disconnected, conn.State);
            // 1 initial success + 3 failed reconnect attempts (CleanupCount = one per establish entry).
            Assert.Equal(4, conn.EstablishCount);
            Assert.Equal(0, conn.ReconnectedCount);
        }

        [Fact]
        public async Task Disconnect_DuringReconnect_StopsTheLoop()
        {
            // Reconnects keep failing; tearing down mid-loop must cancel the supervisor and settle Disconnected.
            var conn = new TestConnection(FastOptions(), ordinal => ordinal == 1);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await conn.ConnectAsync(cts.Token);
            conn.Drop("link loss; reconnects loop forever until teardown");

            await WaitUntilAsync(() => conn.EstablishCount >= 2, cts.Token); // a reconnect attempt has run
            await conn.DisposeAsync();

            Assert.Equal(VpnConnectionState.Disconnected, conn.State);
            int afterTeardown = conn.EstablishCount;
            await Task.Delay(50, cts.Token);
            Assert.Equal(afterTeardown, conn.EstablishCount); // the loop really stopped
        }

        [Fact]
        public void DefaultReconnectOptions_HaveTheSharedDefaults()
        {
            var o = new VpnReconnectOptions();
            Assert.True(o.Enabled);
            Assert.Equal(0, o.MaxAttempts);
            Assert.Equal(TimeSpan.FromSeconds(1), o.InitialBackoff);
            Assert.Equal(TimeSpan.FromSeconds(30), o.MaxBackoff);
            Assert.Equal(2.0, o.BackoffMultiplier);
            Assert.Equal(0.2, o.JitterFraction);
            // NextBackoff doubles then caps at MaxBackoff.
            Assert.Equal(TimeSpan.FromSeconds(2), o.NextBackoff(TimeSpan.FromSeconds(1)));
            Assert.Equal(TimeSpan.FromSeconds(30), o.NextBackoff(TimeSpan.FromSeconds(20)));
        }
    }
}
