using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Tailscale.Control.Noise;
using Xunit;

namespace TqkLibrary.VpnClient.Tailscale.Tests
{
    /// <summary>
    /// The sync <see cref="Stream.Read(byte[],int,int)"/>/<see cref="Stream.Write(byte[],int,int)"/> of
    /// <see cref="Ts2021NoiseStream"/> are real sync twins (not async wrappers): their record frames must be
    /// byte-compatible with the async path in both directions.
    /// </summary>
    public class Ts2021NoiseStreamSyncTests
    {
        static byte[] RandomBytes(int length)
        {
            var b = new byte[length];
            RandomNumberGenerator.Fill(b);
            return b;
        }

        // A payload spanning several records (> MaxPlaintextSize) plus a short tail.
        static byte[] Payload() => RandomBytes(Ts2021Transport.MaxPlaintextSize * 2 + 123);

        static Ts2021NoiseStream Writer(Stream wire, byte[] key) => new(wire, new Ts2021Transport(key), new Ts2021Transport(RandomBytes(32)));
        static Ts2021NoiseStream Reader(Stream wire, byte[] key) => new(wire, new Ts2021Transport(RandomBytes(32)), new Ts2021Transport(key));

        static byte[] ReadAllSync(Stream s, int length)
        {
            byte[] result = new byte[length];
            int read = 0;
            while (read < length)
            {
                int n = s.Read(result, read, Math.Min(1000, length - read)); // small reads exercise the buffered remainder
                Assert.NotEqual(0, n);
                read += n;
            }
            return result;
        }

        static async Task<byte[]> ReadAllAsync(Stream s, int length)
        {
            byte[] result = new byte[length];
            int read = 0;
            while (read < length)
            {
                int n = await s.ReadAsync(result, read, Math.Min(1000, length - read));
                Assert.NotEqual(0, n);
                read += n;
            }
            return result;
        }

        [Fact]
        public void SyncWrite_SyncRead_RoundTrips_AndReturnsZeroAtEof()
        {
            byte[] key = RandomBytes(32), payload = Payload();
            var wire = new MemoryStream();
            Writer(wire, key).Write(payload, 0, payload.Length);

            using var reader = Reader(new MemoryStream(wire.ToArray()), key);
            Assert.Equal(payload, ReadAllSync(reader, payload.Length));
            Assert.Equal(0, reader.Read(new byte[16], 0, 16));
        }

        [Fact]
        public async Task SyncWrite_AsyncRead_Interop()
        {
            byte[] key = RandomBytes(32), payload = Payload();
            var wire = new MemoryStream();
            Writer(wire, key).Write(payload, 0, payload.Length);

            using var reader = Reader(new MemoryStream(wire.ToArray()), key);
            Assert.Equal(payload, await ReadAllAsync(reader, payload.Length));
        }

        [Fact]
        public async Task AsyncWrite_SyncRead_Interop()
        {
            byte[] key = RandomBytes(32), payload = Payload();
            var wire = new MemoryStream();
            await Writer(wire, key).WriteAsync(payload, 0, payload.Length);

            using var reader = Reader(new MemoryStream(wire.ToArray()), key);
            Assert.Equal(payload, ReadAllSync(reader, payload.Length));
        }

        [Fact]
        public async Task MixedSyncAndAsync_ShareRecordState()
        {
            // Nonce counters and the buffered read remainder are shared by both paths: alternate them on one stream pair.
            byte[] key = RandomBytes(32), a = RandomBytes(500), b = RandomBytes(700);
            var wire = new MemoryStream();
            var writer = Writer(wire, key);
            writer.Write(a, 0, a.Length);
            await writer.WriteAsync(b, 0, b.Length);

            using var reader = Reader(new MemoryStream(wire.ToArray()), key);
            byte[] first = new byte[200];
            Assert.Equal(200, reader.Read(first, 0, 200));               // sync: part of record a
            byte[] rest = await ReadAllAsync(reader, 300);                // async: remainder of record a
            byte[] second = ReadAllSync(reader, b.Length);                // sync: record b
            Assert.Equal(a, Concat(first, rest));
            Assert.Equal(b, second);
        }

        [Fact]
        public void SyncRead_TruncatedRecord_Throws()
        {
            byte[] key = RandomBytes(32), payload = RandomBytes(100);
            var wire = new MemoryStream();
            Writer(wire, key).Write(payload, 0, payload.Length);
            byte[] truncated = wire.ToArray().AsSpan(0, (int)wire.Length - 10).ToArray();

            using var reader = Reader(new MemoryStream(truncated), key);
            Assert.ThrowsAny<IOException>(() => reader.Read(new byte[200], 0, 200));
        }

        static byte[] Concat(byte[] x, byte[] y)
        {
            byte[] r = new byte[x.Length + y.Length];
            Buffer.BlockCopy(x, 0, r, 0, x.Length);
            Buffer.BlockCopy(y, 0, r, x.Length, y.Length);
            return r;
        }
    }
}
