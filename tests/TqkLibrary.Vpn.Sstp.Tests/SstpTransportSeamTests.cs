using System.Security.Cryptography.X509Certificates;
using System.Text;
using TqkLibrary.Vpn.Drivers.Sstp;
using TqkLibrary.Vpn.Drivers.Sstp.Enums;
using TqkLibrary.Vpn.Drivers.Sstp.Models;
using TqkLibrary.Vpn.Drivers.Sstp.Transport;
using Xunit;

namespace TqkLibrary.Vpn.Sstp.Tests
{
    /// <summary>
    /// Offline coverage for the <see cref="ITlsByteStream"/> seam introduced in P0.1: the SSTP_DUPLEX_POST handshake
    /// and the 4-byte control/data framing run over a fake in-memory byte stream, with no live server.
    /// </summary>
    public class SstpTransportSeamTests
    {
        [Fact]
        public async Task Connect_PerformsDuplexPost_AndAcceptsHttp200()
        {
            var stream = new FakeTlsByteStream();
            stream.EnqueueInbound(Encoding.ASCII.GetBytes("HTTP/1.1 200\r\n\r\n"));
            using var transport = new SstpTransport(stream, "vpn.example");

            await transport.ConnectAsync();

            Assert.True(stream.Connected);
            string request = Encoding.ASCII.GetString(stream.Outbound.ToArray());
            Assert.StartsWith("SSTP_DUPLEX_POST ", request);
            Assert.Contains("Host: vpn.example\r\n", request);
        }

        [Fact]
        public async Task Connect_NonHttp200_Throws()
        {
            var stream = new FakeTlsByteStream();
            stream.EnqueueInbound(Encoding.ASCII.GetBytes("HTTP/1.1 401 Unauthorized\r\n\r\n"));
            using var transport = new SstpTransport(stream, "vpn.example");

            await Assert.ThrowsAsync<InvalidOperationException>(() => transport.ConnectAsync());
        }

        [Fact]
        public async Task SendControl_FramesWithVersionAndControlBit()
        {
            var stream = new FakeTlsByteStream();
            using var transport = new SstpTransport(stream);

            await transport.SendControlAsync(SstpMessageType.EchoRequest, Array.Empty<SstpAttribute>());

            byte[] sent = stream.Outbound.ToArray();
            Assert.Equal(SstpConstants.Version, sent[0]);
            Assert.Equal(0x01, sent[1] & 0x01);                 // control bit set
            int length = ((sent[2] & 0x0F) << 8) | sent[3];
            Assert.Equal(sent.Length, length);                  // SSTP length covers the whole packet
        }

        [Fact]
        public async Task SendData_FramesWithControlBitClear()
        {
            var stream = new FakeTlsByteStream();
            using var transport = new SstpTransport(stream);

            await transport.SendDataAsync(new byte[] { 1, 2, 3 });

            byte[] sent = stream.Outbound.ToArray();
            Assert.Equal(7, sent.Length);                       // 4-byte header + 3 payload
            Assert.Equal(0x00, sent[1] & 0x01);                 // control bit clear
            Assert.Equal(new byte[] { 1, 2, 3 }, sent[4..]);
        }

        [Fact]
        public async Task ReadPacket_RoundTripsAFramedDataPacket()
        {
            // Frame a data packet with one transport, replay its bytes into a second transport's inbound stream.
            var writeStream = new FakeTlsByteStream();
            using (var writer = new SstpTransport(writeStream))
                await writer.SendDataAsync(new byte[] { 9, 8, 7, 6 });

            var readStream = new FakeTlsByteStream();
            readStream.EnqueueInbound(writeStream.Outbound.ToArray());
            using var reader = new SstpTransport(readStream);

            (bool isControl, byte[] body) = await reader.ReadPacketAsync();

            Assert.False(isControl);
            Assert.Equal(new byte[] { 9, 8, 7, 6 }, body);
        }

        [Fact]
        public void ServerCertificate_DelegatesToTheStream()
        {
            using var cert = SelfSigned();
            var stream = new FakeTlsByteStream { RemoteCertificate = cert };
            using var transport = new SstpTransport(stream);

            Assert.Same(cert, transport.ServerCertificate);
        }

        [Fact]
        public async Task ReadPacket_WhenServerHangs_ThrowsTimeoutException()
        {
            // A server that accepts the connection but never sends a byte: the read-timeout (P1.5) must surface this
            // instead of blocking forever, so the supervisor can treat it as a drop and reconnect.
            using var transport = new SstpTransport(new BlockingTlsByteStream(), readTimeout: TimeSpan.FromMilliseconds(50));

            await Assert.ThrowsAsync<TimeoutException>(() => transport.ReadPacketAsync());
        }

        [Fact]
        public async Task ReadPacket_WhenCallerCancels_PropagatesCancellation_NotTimeout()
        {
            // Caller-driven cancellation must stay an OperationCanceledException — never be remapped to a timeout —
            // so teardown is not misreported as a hung server.
            using var transport = new SstpTransport(new BlockingTlsByteStream(), readTimeout: TimeSpan.FromSeconds(30));
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => transport.ReadPacketAsync(cts.Token));
        }

        [Fact]
        public async Task ReadPacket_WithTimeoutEnabled_StillRoundTripsPromptData()
        {
            // The timeout wrapper must be transparent when data arrives in time.
            var writeStream = new FakeTlsByteStream();
            using (var writer = new SstpTransport(writeStream))
                await writer.SendDataAsync(new byte[] { 5, 4, 3 });

            var readStream = new FakeTlsByteStream();
            readStream.EnqueueInbound(writeStream.Outbound.ToArray());
            using var reader = new SstpTransport(readStream, readTimeout: TimeSpan.FromSeconds(30));

            (bool isControl, byte[] body) = await reader.ReadPacketAsync();

            Assert.False(isControl);
            Assert.Equal(new byte[] { 5, 4, 3 }, body);
        }

        static X509Certificate2 SelfSigned()
        {
            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            var request = new CertificateRequest("CN=sstp-seam-test", rsa,
                System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            return request.CreateSelfSigned(System.DateTimeOffset.UnixEpoch, System.DateTimeOffset.UnixEpoch.AddYears(1));
        }

        /// <summary>An in-memory <see cref="ITlsByteStream"/>: records written bytes and replays a scripted inbound buffer.</summary>
        sealed class FakeTlsByteStream : ITlsByteStream
        {
            readonly Queue<byte> _inbound = new();

            public List<byte> Outbound { get; } = new();
            public bool Connected { get; private set; }
            public X509Certificate2? RemoteCertificate { get; set; }

            public void EnqueueInbound(byte[] bytes)
            {
                foreach (byte b in bytes) _inbound.Enqueue(b);
            }

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default)
            {
                Connected = true;
                return default;
            }

            public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                int n = 0;
                while (n < buffer.Length && _inbound.Count > 0)
                    buffer.Span[n++] = _inbound.Dequeue();
                return new ValueTask<int>(n);   // 0 = stream exhausted (closed)
            }

            public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            {
                Outbound.AddRange(buffer.ToArray());
                return default;
            }

            public ValueTask DisposeAsync() => default;
        }

        /// <summary>An <see cref="ITlsByteStream"/> that connects but never produces inbound data; a read completes only
        /// when its <see cref="CancellationToken"/> fires (the read-timeout or caller cancellation), modelling a hung server.</summary>
        sealed class BlockingTlsByteStream : ITlsByteStream
        {
            public X509Certificate2? RemoteCertificate => null;

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                var tcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
                using (cancellationToken.Register(() => tcs.TrySetCanceled(cancellationToken)))
                    return await tcs.Task.ConfigureAwait(false);
            }

            public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => default;

            public ValueTask DisposeAsync() => default;
        }
    }
}
