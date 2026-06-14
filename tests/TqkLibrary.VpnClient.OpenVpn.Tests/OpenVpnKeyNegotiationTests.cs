using System.Text;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Drives the real client <see cref="OpenVpnKeyNegotiation"/> over an in-memory duplex stream against a throwaway
    /// "server" that parses the client message and replies — exercising the on-wire framing of key-method-2. Both ends
    /// must derive complementary keys, and a data packet must then round-trip through them. Server role = test harness.
    /// </summary>
    public class OpenVpnKeyNegotiationTests
    {
        [Fact]
        public async Task NegotiateAsync_ExchangesKeyMethod2_AndDerivesMatchingKeys()
        {
            var (clientStream, serverStream) = LoopbackStream.CreatePair();
            const ulong clientSid = 0xC1C2C3C4C5C6C7C8UL;
            const ulong serverSid = 0x1122334455667788UL;
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            OpenVpnDataChannelKeys? serverKeys = null;
            Task serverTask = Task.Run(async () =>
            {
                // Read the client key-method-2 message: 117 fixed bytes + 3 P_strings (options, user, pass).
                byte[] fixedPart = await ReadExactAsync(serverStream, 117, cts.Token);
                var clientKs = new OpenVpnKeySource2(
                    fixedPart.AsSpan(5, 48).ToArray(),
                    fixedPart.AsSpan(53, 32).ToArray(),
                    fixedPart.AsSpan(85, 32).ToArray());
                await ReadStringAsync(serverStream, cts.Token); // options
                await ReadStringAsync(serverStream, cts.Token); // username
                await ReadStringAsync(serverStream, cts.Token); // password

                var serverKs = ServerKeySource();
                byte[] reply = BuildServerMessage(serverKs, "V4,cipher AES-256-GCM");
                await serverStream.WriteAsync(reply, 0, reply.Length, cts.Token);
                await serverStream.FlushAsync(cts.Token);

                serverKeys = OpenVpnKeyMethod2.DeriveDataKeys(clientKs, serverKs, clientSid, serverSid, isServer: true);
            });

            var negotiation = new OpenVpnKeyNegotiation(clientStream, clientSid, serverSid);
            OpenVpnDataChannelKeys clientKeys = await negotiation.NegotiateAsync("V4,cipher AES-256-GCM",
                username: "user", password: "pass", cancellationToken: cts.Token);
            await serverTask;

            Assert.NotNull(serverKeys);
            Assert.Equal(clientKeys.SendCipherKey, serverKeys!.ReceiveCipherKey);
            Assert.Equal(clientKeys.ReceiveCipherKey, serverKeys.SendCipherKey);

            // Data flows through the negotiated keys.
            var clientDc = new OpenVpnDataChannel(clientKeys);
            var serverDc = new OpenVpnDataChannel(serverKeys);
            byte[] payload = Encoding.ASCII.GetBytes("data over negotiated keys");
            Assert.True(serverDc.TryUnprotect(clientDc.Protect(payload), out byte[] got));
            Assert.Equal(payload, got);
        }

        static OpenVpnKeySource2 ServerKeySource()
        {
            byte[] r1 = new byte[OpenVpnKeySource2.RandomSize], r2 = new byte[OpenVpnKeySource2.RandomSize];
            for (int i = 0; i < r1.Length; i++) { r1[i] = (byte)(0x30 + i); r2[i] = (byte)(0x80 + i); }
            return new OpenVpnKeySource2(Array.Empty<byte>(), r1, r2);
        }

        static byte[] BuildServerMessage(OpenVpnKeySource2 server, string options)
        {
            var buf = new List<byte>();
            buf.AddRange(new byte[4]);
            buf.Add(2);
            buf.AddRange(server.Random1);
            buf.AddRange(server.Random2);
            byte[] opt = Encoding.ASCII.GetBytes(options);
            int len = opt.Length + 1;
            buf.Add((byte)(len >> 8));
            buf.Add((byte)len);
            buf.AddRange(opt);
            buf.Add(0);
            return buf.ToArray();
        }

        static async Task<byte[]> ReadExactAsync(Stream s, int count, CancellationToken ct)
        {
            byte[] buf = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n = await s.ReadAsync(buf, read, count - read, ct);
                if (n == 0) throw new EndOfStreamException();
                read += n;
            }
            return buf;
        }

        static async Task ReadStringAsync(Stream s, CancellationToken ct)
        {
            byte[] lenBytes = await ReadExactAsync(s, 2, ct);
            int len = (lenBytes[0] << 8) | lenBytes[1];
            if (len > 0) await ReadExactAsync(s, len, ct);
        }

        /// <summary>A minimal in-memory duplex stream: each side's writes are the other side's reads (byte-queue + waiter).</summary>
        sealed class LoopbackStream : Stream
        {
            readonly object _gate = new();
            readonly Queue<byte[]> _inbound = new();
            byte[]? _partial;
            int _partialPos;
            TaskCompletionSource<bool>? _waiter;
            LoopbackStream _peer = null!;

            public static (LoopbackStream, LoopbackStream) CreatePair()
            {
                var a = new LoopbackStream();
                var b = new LoopbackStream();
                a._peer = b;
                b._peer = a;
                return (a, b);
            }

            void Enqueue(byte[] data)
            {
                TaskCompletionSource<bool>? signal;
                lock (_gate) { _inbound.Enqueue(data); signal = _waiter; _waiter = null; }
                signal?.TrySetResult(true);
            }

            public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                while (true)
                {
                    TaskCompletionSource<bool> tcs;
                    lock (_gate)
                    {
                        if (_partial is null && _inbound.Count > 0) { _partial = _inbound.Dequeue(); _partialPos = 0; }
                        if (_partial is not null)
                        {
                            int n = Math.Min(count, _partial.Length - _partialPos);
                            Array.Copy(_partial, _partialPos, buffer, offset, n);
                            _partialPos += n;
                            if (_partialPos >= _partial.Length) _partial = null;
                            return n;
                        }
                        _waiter ??= new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                        tcs = _waiter;
                    }
                    using (cancellationToken.Register(() => tcs.TrySetCanceled())) await tcs.Task.ConfigureAwait(false);
                }
            }

            public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                byte[] copy = new byte[count];
                Array.Copy(buffer, offset, copy, 0, count);
                _peer.Enqueue(copy);
                return Task.CompletedTask;
            }

            public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
            public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
            public override bool CanRead => true;
            public override bool CanWrite => true;
            public override bool CanSeek => false;
            public override void Flush() { }
            public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
        }
    }
}
