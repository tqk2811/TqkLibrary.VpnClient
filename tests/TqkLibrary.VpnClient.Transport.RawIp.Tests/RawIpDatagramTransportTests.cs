using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.RawIp.Tests
{
    /// <summary>
    /// <see cref="RawIpDatagramTransport"/>'s overlapped send/receive without elevation: a loopback <b>UDP</b> socket
    /// stands in for the raw socket (the transport only needs a datagram <see cref="Socket"/>), and each UDP payload is
    /// shaped like what a raw IPv4 socket delivers — an IPv4 header in front of the protocol payload — so the source
    /// filter and header stripping run exactly as on a real raw socket.
    /// </summary>
    public class RawIpDatagramTransportTests
    {
        const int Guard = 5000;

        [Fact]
        public async Task Receive_StripsTheIpv4Header_AndSkipsOtherSources()
        {
            using var local = Bind(IPAddress.Loopback);
            using var stranger = Bind(IPAddress.Parse("127.0.0.2"));
            using var gateway = Bind(IPAddress.Loopback);
            IPEndPoint target = (IPEndPoint)local.LocalEndPoint!;
            await using var transport = new RawIpDatagramTransport(local, IPAddress.Loopback);

            stranger.SendTo(WrapInIpv4(new byte[] { 9, 9 }), target);          // wrong source: skipped
            byte[] fragment = WrapInIpv4(new byte[] { 8, 8 });
            fragment[6] = 0x20;                                                 // More-Fragments: dropped
            gateway.SendTo(fragment, target);
            gateway.SendTo(WrapInIpv4(new byte[] { 1, 2, 3 }), target);

            using var cts = new CancellationTokenSource(Guard);
            byte[] buffer = new byte[16];
            int n = await transport.ReceiveAsync(buffer, cts.Token);
            Assert.Equal(new byte[] { 1, 2, 3 }, buffer.AsSpan(0, n).ToArray());
        }

        [Fact]
        public async Task CancellingAPendingReceive_ReturnsPromptly_AndTheTransportStillReceives()
        {
            using var local = Bind(IPAddress.Loopback);
            using var gateway = Bind(IPAddress.Loopback);
            await using var transport = new RawIpDatagramTransport(local, IPAddress.Loopback);

            // The old poll loop only noticed cancellation at its next 250 ms receive timeout. Each round here cancels
            // 30 ms into a fresh receive, so the old code took ~220 ms EVERY round; an overlapped receive is cancelled
            // at once (a few ms). The median of the rounds separates the two with a wide margin and, unlike an average,
            // is not dragged over the bound by one or two rounds a loaded machine happened to stall.
            const int rounds = 9;
            var samples = new List<long>();
            for (int i = 0; i < rounds; i++)
            {
                using var cts = new CancellationTokenSource();
                Task<int> pending = transport.ReceiveAsync(new byte[16], cts.Token).AsTask();
                await Task.Delay(30);
                Assert.False(pending.IsCompleted);

                var sw = Stopwatch.StartNew();
                cts.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
                samples.Add(sw.ElapsedMilliseconds);
            }
            samples.Sort();
            long median = samples[rounds / 2];
            Assert.True(median < 100, $"cancellation took {median} ms (median of {string.Join(",", samples)}): it waited for a poll timeout");

            // net6+: cancelling aborted only that receive, not the socket.
            gateway.SendTo(WrapInIpv4(new byte[] { 7 }), local.LocalEndPoint!);
            using var guard = new CancellationTokenSource(Guard);
            byte[] buffer = new byte[16];
            Assert.Equal(1, await transport.ReceiveAsync(buffer, guard.Token));
            Assert.Equal(7, buffer[0]);
        }

        [Fact]
        public async Task Dispose_EndsAPendingReceive()
        {
            using var local = Bind(IPAddress.Loopback);
            var transport = new RawIpDatagramTransport(local, IPAddress.Loopback);
            Task<int> pending = transport.ReceiveAsync(new byte[16]).AsTask();
            await Task.Delay(50);
            Assert.False(pending.IsCompleted);

            await transport.DisposeAsync();
            Assert.True(await Task.WhenAny(pending, Task.Delay(Guard)) == pending, "a receive pending across Dispose never ended");
            await Assert.ThrowsAnyAsync<Exception>(() => pending);
        }

        static Socket Bind(IPAddress address)
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(address, 0));
            return socket;
        }

        // A minimal 20-byte IPv4 header in front of the payload, as a raw IPv4 socket delivers it.
        static byte[] WrapInIpv4(byte[] payload)
        {
            byte[] datagram = new byte[20 + payload.Length];
            datagram[0] = 0x45;
            datagram[2] = (byte)(datagram.Length >> 8);
            datagram[3] = (byte)datagram.Length;
            datagram[8] = 64;
            datagram[9] = 50;
            payload.CopyTo(datagram, 20);
            return datagram;
        }
    }
}
