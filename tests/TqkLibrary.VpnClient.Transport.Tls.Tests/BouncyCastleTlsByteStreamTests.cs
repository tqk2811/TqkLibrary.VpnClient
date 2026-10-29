using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TqkLibrary.VpnClient.Transport.Tls;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.Tls.Tests
{
    /// <summary>
    /// <see cref="BouncyCastleTlsByteStream"/>'s data path after the handshake: a dedicated reader thread feeds
    /// <c>ReadAsync</c> and a dedicated writer thread drains what <c>WriteAsync</c> queues, against a loopback SslStream server driven from its own
    /// thread (synchronous I/O there, so the server never competes for the pool these tests reason about).
    /// </summary>
    [Collection(ThreadPoolStarvationCollection.Name)]
    public class BouncyCastleTlsByteStreamTests
    {
        const int Guard = 10000;

        [Fact]
        public async Task ByteAtATimeReads_SpanRecords_WithoutLosingOrOverReading()
        {
            using var server = TlsLoopbackServer.Start();
            using var client = await server.ConnectClientAsync();

            server.Ssl.Write(Encoding.ASCII.GetBytes("hello"));     // one TLS record
            server.Ssl.Write(Encoding.ASCII.GetBytes("world!"));    // a second record
            server.Ssl.Flush();

            var got = new StringBuilder();
            byte[] one = new byte[1];
            using var cts = new CancellationTokenSource(Guard);
            for (int i = 0; i < 11; i++)
            {
                Assert.Equal(1, await client.ReadAsync(one, cts.Token));
                got.Append((char)one[0]);
            }
            Assert.Equal("helloworld!", got.ToString());
        }

        [Fact]
        public async Task CloseNotify_ReturnsZero_AndKeepsReturningZero()
        {
            using var server = TlsLoopbackServer.Start();
            using var client = await server.ConnectClientAsync();

            server.Ssl.Write(Encoding.ASCII.GetBytes("bye"));
            server.Ssl.ShutdownAsync().GetAwaiter().GetResult();   // close_notify
            server.Tcp.Client.Shutdown(SocketShutdown.Send);

            using var cts = new CancellationTokenSource(Guard);
            byte[] buffer = new byte[16];
            Assert.Equal(3, await client.ReadAsync(buffer, cts.Token));
            Assert.Equal(0, await client.ReadAsync(buffer, cts.Token));
            Assert.Equal(0, await client.ReadAsync(buffer, cts.Token));
        }

        [Fact]
        public async Task ServerReset_Throws()
        {
            using var server = TlsLoopbackServer.Start();
            using var client = await server.ConnectClientAsync();

            server.Tcp.Client.LingerState = new LingerOption(true, 0);   // RST on close
            server.Tcp.Client.Close();

            using var cts = new CancellationTokenSource(Guard);
            await Assert.ThrowsAnyAsync<Exception>(async () =>
            {
                // Some stacks surface the reset as EOF on a first read only after an attempted write; a reset
                // must still never be reported as data.
                while (true)
                {
                    int n = await client.ReadAsync(new byte[16], cts.Token);
                    Assert.True(n <= 0, "a reset connection returned data");
                    if (n == 0) throw new EndOfStreamException("reset reported as end of stream");
                }
            });
        }

        [Fact]
        public async Task CancelledRead_ReturnsPromptly_AndTheNextReadGetsEveryByte()
        {
            using var server = TlsLoopbackServer.Start();
            using var client = await server.ConnectClientAsync();
            byte[] buffer = new byte[64];

            using (var cancel = new CancellationTokenSource(100))
            {
                var sw = Stopwatch.StartNew();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ReadAsync(buffer, cancel.Token).AsTask());
                Assert.True(sw.ElapsedMilliseconds < 2000, "a cancelled read did not return promptly");
            }

            server.Ssl.Write(Encoding.ASCII.GetBytes("after-cancel"));
            server.Ssl.Flush();

            using var cts = new CancellationTokenSource(Guard);
            var got = new StringBuilder();
            while (got.Length < "after-cancel".Length)
            {
                int n = await client.ReadAsync(buffer, cts.Token);
                Assert.True(n > 0);
                got.Append(Encoding.ASCII.GetString(buffer, 0, n));
            }
            Assert.Equal("after-cancel", got.ToString());
        }

        [Fact]
        public async Task Write_RoundTrips()
        {
            using var server = TlsLoopbackServer.Start();
            using var client = await server.ConnectClientAsync();

            await client.WriteAsync(Encoding.ASCII.GetBytes("ping"));
            byte[] buffer = new byte[4];
            int read = 0;
            while (read < 4) read += server.Ssl.Read(buffer, read, 4 - read);
            Assert.Equal("ping", Encoding.ASCII.GetString(buffer));
        }

        [Fact]
        public async Task Dispose_EndsThePendingRead_AndTheReaderThread()
        {
            using var server = TlsLoopbackServer.Start();
            var client = await server.ConnectClientAsync();
            Task<int> pending = client.ReadAsync(new byte[16]).AsTask();
            await Task.Delay(50);
            Thread reader = client.ReaderThread ?? throw new InvalidOperationException("the first read did not start the reader thread");

            client.Dispose();

            Assert.True(reader.Join(Guard), "the reader thread outlived Dispose");
            // Not 0: a driver's read loop must not mistake its own teardown for the peer closing the session.
            var error = await Assert.ThrowsAnyAsync<Exception>(() => pending.WaitAsync(TimeSpan.FromMilliseconds(Guard)));
            Assert.IsType<ObjectDisposedException>(error);
        }

        [Fact]
        public async Task ReadAfterDispose_Throws_AndStartsNoReaderThread()
        {
            using var server = TlsLoopbackServer.Start();
            var client = await server.ConnectClientAsync();
            client.Dispose();

            await Assert.ThrowsAsync<ObjectDisposedException>(() => client.ReadAsync(new byte[16]).AsTask());
            Assert.Null(client.ReaderThread);
        }

        [Fact]
        public async Task Writes_ReturnWithoutWaitingForTheSocket_AndArriveInOrder()
        {
            using var server = TlsLoopbackServer.Start();
            using var client = await server.ConnectClientAsync();

            // The server reads nothing yet: the writer thread soon blocks on a full send buffer, but WriteAsync only
            // queues (up to 64 chunks), so every call here completes at once.
            const int chunks = 48, size = 64 * 1024;
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < chunks; i++)
            {
                ValueTask write = client.WriteAsync(Chunk(i, size));
                Assert.True(write.IsCompleted, $"write {i} waited for the socket");
                await write;
            }
            Assert.True(sw.ElapsedMilliseconds < 2000, "queued writes were slow");

            byte[] received = new byte[chunks * size];
            int read = 0;
            while (read < received.Length) read += server.Ssl.Read(received, read, received.Length - read);
            for (int i = 0; i < chunks; i++)
                Assert.Equal(Chunk(i, size), received.AsSpan(i * size, size).ToArray());
        }

        [Fact]
        public async Task WriteFailure_SurfacesOnALaterWrite_AsIOException()
        {
            using var server = TlsLoopbackServer.Start();
            using var client = await server.ConnectClientAsync();
            server.Tcp.Client.LingerState = new LingerOption(true, 0);   // RST on close
            server.Tcp.Client.Close();

            var sw = Stopwatch.StartNew();
            Exception? error = null;
            while (error is null && sw.ElapsedMilliseconds < Guard)
            {
                try { await client.WriteAsync(new byte[1024]); }
                catch (Exception ex) { error = ex; }
                await Task.Delay(10);
            }
            Assert.IsType<IOException>(error);
            Assert.NotNull(error!.InnerException);
        }

        [Fact]
        public async Task Dispose_EndsTheWriterThread()
        {
            using var server = TlsLoopbackServer.Start();
            var client = await server.ConnectClientAsync();
            await client.WriteAsync(Encoding.ASCII.GetBytes("last"));
            Thread writer = client.WriterThread ?? throw new InvalidOperationException("the first write did not start the writer thread");

            client.Dispose();

            Assert.True(writer.Join(Guard), "the writer thread outlived Dispose");
            // What was queued before Dispose still went out (a final control frame must not be lost).
            byte[] buffer = new byte[4];
            int read = 0;
            while (read < 4) read += server.Ssl.Read(buffer, read, 4 - read);
            Assert.Equal("last", Encoding.ASCII.GetString(buffer));
            await Assert.ThrowsAsync<ObjectDisposedException>(() => client.WriteAsync(new byte[1]).AsTask());
        }

        static byte[] Chunk(int index, int size)
        {
            byte[] chunk = new byte[size];
            for (int i = 0; i < size; i++) chunk[i] = (byte)(index * 31 + i);
            return chunk;
        }

        [Fact]
        public async Task Write_CompletesWhileTheThreadPoolIsStarved()
        {
            using var server = TlsLoopbackServer.Start();
            using var client = await server.ConnectClientAsync();
            byte[] payload = Encoding.ASCII.GetBytes("starved");

            Task write;
            using (ThreadPoolStarvation.Start())
            {
                write = Task.Factory.StartNew(() => client.WriteAsync(payload).AsTask().Wait(),
                    CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);   // its own thread
                Assert.True(write.Wait(ThreadPoolStarvation.StarvedWakeBound), "WriteAsync needed a thread-pool thread");
            }

            byte[] buffer = new byte[payload.Length];
            int read = 0;
            while (read < buffer.Length) read += server.Ssl.Read(buffer, read, buffer.Length - read);
            Assert.Equal(payload, buffer);
        }

        /// <summary>Accepts one TLS 1.2 client on loopback; the server side runs synchronously on its own thread.</summary>
        sealed class TlsLoopbackServer : IDisposable
        {
            readonly TcpListener _listener;
            readonly X509Certificate2 _cert;
            readonly Thread _accept;
            readonly ManualResetEventSlim _ready = new(false);
            Exception? _error;

            TlsLoopbackServer()
            {
                _cert = CreateServerCert();
                _listener = new TcpListener(IPAddress.Loopback, 0);
                _listener.Start();
                _accept = new Thread(Accept) { IsBackground = true, Name = "TLS test server" };
                _accept.Start();
            }

            public static TlsLoopbackServer Start() => new();

            public TcpClient Tcp { get; private set; } = null!;
            public SslStream Ssl { get; private set; } = null!;

            public async Task<BouncyCastleTlsByteStream> ConnectClientAsync()
            {
                int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
                var client = new BouncyCastleTlsByteStream("127.0.0.1", new IPEndPoint(IPAddress.Loopback, port));
                using var cts = new CancellationTokenSource(Guard);
                await client.ConnectAsync(cts.Token);
                Assert.True(_ready.Wait(Guard), "server handshake did not finish");
                if (_error is not null) throw new InvalidOperationException("server handshake failed", _error);
                return client;
            }

            void Accept()
            {
                try
                {
                    Tcp = _listener.AcceptTcpClient();
                    Ssl = new SslStream(Tcp.GetStream(), leaveInnerStreamOpen: true);
                    Ssl.AuthenticateAsServer(_cert, clientCertificateRequired: false, SslProtocols.Tls12, checkCertificateRevocation: false);
                }
                catch (Exception ex) { _error = ex; }
                finally { _ready.Set(); }
            }

            public void Dispose()
            {
                try { Ssl?.Dispose(); } catch { }
                try { Tcp?.Dispose(); } catch { }
                _listener.Stop();
                _cert.Dispose();
            }

            static X509Certificate2 CreateServerCert()
            {
                using var rsa = RSA.Create(2048);
                var request = new CertificateRequest("CN=bc-tls-transport-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddYears(10));
                return new X509Certificate2(ephemeral.Export(X509ContentType.Pfx));
            }
        }
    }

    /// <summary>Tests that starve the thread pool must not run beside tests that need it.</summary>
    [CollectionDefinition(Name, DisableParallelization = true)]
    public sealed class ThreadPoolStarvationCollection
    {
        public const string Name = "ThreadPoolStarvation";
    }

    /// <summary>Queues far more blocking work items than the pool has threads (same technique as the IpStack tests).</summary>
    internal static class ThreadPoolStarvation
    {
        /// <summary>Far below what a pool-dependent wake-up needs behind ~4x MinThreads blocked items.</summary>
        public const int StarvedWakeBound = 1500;

        public static IDisposable Start()
        {
            var gate = new ManualResetEventSlim(false);
            ThreadPool.GetMinThreads(out int workers, out _);
            int count = Math.Max(64, workers * 4);
            for (int i = 0; i < count; i++)
                ThreadPool.UnsafeQueueUserWorkItem(_ => gate.Wait(20000), null);
            Thread.Sleep(50);
            return new Release(gate);
        }

        sealed class Release : IDisposable
        {
            readonly ManualResetEventSlim _gate;
            public Release(ManualResetEventSlim gate) => _gate = gate;
            public void Dispose() => _gate.Set();
        }
    }
}
