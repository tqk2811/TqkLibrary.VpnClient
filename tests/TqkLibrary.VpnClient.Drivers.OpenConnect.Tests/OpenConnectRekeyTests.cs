using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.OpenConnect.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Tests
{
    /// <summary>
    /// Drives the V.5 CSTP session-rekey path offline: the gateway pushes <c>X-CSTP-Rekey-Method</c>/<c>X-CSTP-Rekey-Time</c>
    /// on CONNECT, a controllable clock pushes the driver's 1 s timer past the rekey period, and the driver re-establishes
    /// a fresh tunnel make-before-break (a new auth + CONNECT against a fresh in-process responder) and swaps the data
    /// plane onto it. The tunnel must stay <c>Connected</c> throughout and keep carrying traffic. Both <c>new-tunnel</c>
    /// and the <c>ssl</c> fallback re-establish (SslStream exposes no client TLS renegotiation on net8/netstandard2.0).
    /// </summary>
    public class OpenConnectRekeyTests
    {
        const string User = "alice";
        const string Pass = "s3cret";

        [Fact]
        public async Task Rekey_NewTunnel_FiresAtRekeyTime_ReestablishesWithoutDroppingAndRoundTrips()
        {
            var clock = new MutableClock();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            // Fresh server per connect; each rekey re-establish gets a new tunnel (a different address proves the swap).
            // DPD disabled (dpdSeconds:0) so the single large clock jump exercises the rekey timer, not dead-detection.
            var factory = new MultiAttemptOpenConnectFactory(User, Pass, dpdSeconds: 0, keepaliveSeconds: 0,
                rekeyMethod: "new-tunnel", rekeyTime: 60,
                addressForAttempt: attempt => attempt == 1 ? "10.10.0.5" : "10.10.0.9");

            var connection = new OpenConnectConnection("127.0.0.1", 443, factory, User, Pass, clock: clock.Now);
            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);
            Assert.Equal(VpnConnectionState.Connected, connection.State);
            Assert.Equal(OpenConnectRekeyMethod.NewTunnel, connection.RekeyMethod);
            Assert.Equal(1, factory.Attempts);

            // Push past the 60 s rekey period → the timer triggers a make-before-break re-establish.
            clock.Advance(61_000);
            await WaitUntilAsync(() => connection.RekeyCount >= 1, cts.Token);

            // The tunnel never dropped and a fresh tunnel was opened (a 2nd connect through the factory).
            Assert.Equal(VpnConnectionState.Connected, connection.State);
            Assert.True(factory.Attempts >= 2, $"expected a re-establish, attempts={factory.Attempts}");
            Assert.Equal(IPAddress.Parse("10.10.0.9"), connection.AssignedAddress); // swapped onto the new tunnel

            // The stable facade still carries traffic — over the freshly re-established tunnel.
            byte[] packet = Encoding.ASCII.GetBytes("a packet after the make-before-break rekey");
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(packet, echoed);
            Assert.Equal(1, factory.LastServer!.DataPacketsReceived); // the echo came from the new server

            await connection.DisposeAsync();
            factory.StopAll();
        }

        [Fact]
        public async Task Rekey_SslMethod_FallsBackToReestablish()
        {
            var clock = new MutableClock();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            // ssl rekey is not reachable via SslStream renegotiation on these TFMs ⇒ the driver re-establishes instead.
            var factory = new MultiAttemptOpenConnectFactory(User, Pass, dpdSeconds: 0, keepaliveSeconds: 0,
                rekeyMethod: "ssl", rekeyTime: 60);

            var connection = new OpenConnectConnection("127.0.0.1", 443, factory, User, Pass, clock: clock.Now);
            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);
            Assert.Equal(OpenConnectRekeyMethod.Ssl, connection.RekeyMethod);

            clock.Advance(61_000);
            await WaitUntilAsync(() => connection.RekeyCount >= 1, cts.Token);

            Assert.Equal(VpnConnectionState.Connected, connection.State);
            Assert.True(factory.Attempts >= 2); // ssl ⇒ re-establish

            byte[] packet = Encoding.ASCII.GetBytes("traffic after an ssl-method rekey (re-established)");
            await connection.PacketChannel.WriteIpPacketAsync(packet, cts.Token);
            Assert.Equal(packet, await inbound.Reader.ReadAsync(cts.Token));

            await connection.DisposeAsync();
            factory.StopAll();
        }

        [Fact]
        public async Task NoRekey_WhenServerDoesNotAdvertiseRekeyTime()
        {
            var clock = new MutableClock();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            // No X-CSTP-Rekey-Time (rekeyTime:0) ⇒ rekey disabled; advancing the clock must NOT re-establish.
            // DPD disabled so the big clock jump does not trip dead-detection (we are isolating the rekey timer).
            var factory = new MultiAttemptOpenConnectFactory(User, Pass, dpdSeconds: 0, keepaliveSeconds: 0,
                rekeyMethod: "ssl", rekeyTime: 0);

            var connection = new OpenConnectConnection("127.0.0.1", 443, factory, User, Pass, clock: clock.Now);
            await connection.ConnectAsync(cts.Token);
            Assert.Equal(OpenConnectRekeyMethod.None, connection.RekeyMethod);

            // Far past any plausible rekey period — but rekey is disabled, so nothing re-establishes.
            clock.Advance(10 * 60_000);
            // Give the 1 s timer several real ticks to (not) act.
            await Task.Delay(250, cts.Token);
            Assert.Equal(0, connection.RekeyCount);
            Assert.Equal(1, factory.Attempts);
            Assert.Equal(VpnConnectionState.Connected, connection.State);

            await connection.DisposeAsync();
            factory.StopAll();
        }

        // ---- helpers ----

        static async Task WaitUntilAsync(Func<bool> condition, CancellationToken ct)
        {
            while (!condition())
            {
                ct.ThrowIfCancellationRequested();
                await Task.Delay(50, ct);
            }
        }

        /// <summary>A monotonic millisecond clock the test advances by hand (the timer still fires on real wall-clock).</summary>
        sealed class MutableClock
        {
            long _value;
            public long Now() => Interlocked.Read(ref _value);
            public void Advance(long ms) => Interlocked.Add(ref _value, ms);
        }
    }
}
