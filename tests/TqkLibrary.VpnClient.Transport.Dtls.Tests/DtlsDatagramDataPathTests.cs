using System;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.Dtls.Tests
{
    /// <summary>
    /// <see cref="DtlsDatagramTransport"/>'s data path after the handshake: a dedicated receive thread queues decrypted
    /// datagrams for <c>ReceiveAsync</c>, and <c>SendAsync</c> encrypts inline. Same in-process echo server and loopback
    /// link as <see cref="DtlsDatagramTransportTests"/> (this assembly runs its tests serially).
    /// </summary>
    public class DtlsDatagramDataPathTests
    {
        const int StarvedWakeBound = 1500;   // far below what a pool-dependent wake-up needs behind ~4x MinThreads blocked items

        static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);

        static async Task<(SimulatedDtlsServer Server, DtlsDatagramTransport Client)> ConnectAsync()
        {
            var link = new LoopbackDatagramLink();
            var server = new SimulatedDtlsServer(link.Server);
            server.Start();
            var client = new DtlsDatagramTransport(link.Client);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await client.ConnectAsync(cts.Token);
            return (server, client);
        }

        [Fact]
        public async Task CancelledReceive_ReturnsPromptly_AndTheNextReceiveGetsTheDatagram()
        {
            var (server, client) = await ConnectAsync();
            using (server)
            {
                byte[] rx = new byte[2048];
                using (var cancel = new CancellationTokenSource(100))
                {
                    var sw = Stopwatch.StartNew();
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ReceiveAsync(rx, cancel.Token).AsTask());
                    Assert.True(sw.ElapsedMilliseconds < 2000, "a cancelled receive did not return promptly");
                }

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.SendAsync(Bytes("after-cancel"), cts.Token);
                int n = await client.ReceiveAsync(rx, cts.Token);
                Assert.Equal("after-cancel", Encoding.UTF8.GetString(rx, 0, n));
                await client.DisposeAsync();
            }
        }

        [Fact]
        public async Task Dispose_FailsThePendingReceive_AndEndsTheReceiveThread()
        {
            var (server, client) = await ConnectAsync();
            using (server)
            {
                Task<int> pending = client.ReceiveAsync(new byte[2048]).AsTask();
                await Task.Delay(50);
                Thread receiver = client.ReceiverThread ?? throw new InvalidOperationException("the first receive did not start the thread");

                await client.DisposeAsync();

                Assert.True(receiver.Join(5000), "the receive thread outlived Dispose");
                await Assert.ThrowsAsync<ObjectDisposedException>(() => pending);
            }
        }

        [Fact]
        public async Task SlowConsumer_DropsTheOldestDatagrams_AndKeepsTheNewest()
        {
            var (server, client) = await ConnectAsync();
            using (server)
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                byte[] rx = new byte[2048];
                await client.SendAsync(Bytes("warm-up"), cts.Token);   // starts the receive thread
                Assert.Equal("warm-up", Encoding.UTF8.GetString(rx, 0, await client.ReceiveAsync(rx, cts.Token)));

                int total = DtlsDatagramTransport.ReceiveQueueCapacity + 40;
                for (int i = 0; i < total; i++)
                    await client.SendAsync(Bytes($"d{i}"), cts.Token);   // echoed back while nobody reads

                var sw = Stopwatch.StartNew();
                while (client.ReceiveDropped < total - DtlsDatagramTransport.ReceiveQueueCapacity && sw.ElapsedMilliseconds < 10000)
                    await Task.Delay(20);

                Assert.Equal(total - DtlsDatagramTransport.ReceiveQueueCapacity, client.ReceiveDropped);
                int first = await client.ReceiveAsync(rx, cts.Token);
                Assert.Equal($"d{total - DtlsDatagramTransport.ReceiveQueueCapacity}", Encoding.UTF8.GetString(rx, 0, first));
                await client.DisposeAsync();
            }
        }

        [Fact]
        public async Task Send_CompletesWhileTheThreadPoolIsStarved()
        {
            var (server, client) = await ConnectAsync();
            using (server)
            {
                var gate = new ManualResetEventSlim(false);
                ThreadPool.GetMinThreads(out int workers, out _);
                for (int i = 0, count = Math.Max(64, workers * 4); i < count; i++)
                    ThreadPool.UnsafeQueueUserWorkItem(_ => gate.Wait(20000), null);
                Thread.Sleep(50);
                try
                {
                    var send = new Thread(() => client.SendAsync(Bytes("starved")).AsTask().Wait()) { IsBackground = true };
                    send.Start();
                    Assert.True(send.Join(StarvedWakeBound), "SendAsync needed a thread-pool thread");
                }
                finally { gate.Set(); }

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                byte[] rx = new byte[2048];
                Assert.Equal("starved", Encoding.UTF8.GetString(rx, 0, await client.ReceiveAsync(rx, cts.Token)));
                await client.DisposeAsync();
            }
        }
    }
}
