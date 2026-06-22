using System;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.IpEncap.Gre;
using Xunit;

namespace TqkLibrary.VpnClient.IpEncap.Tests
{
    /// <summary>
    /// Offline coverage for the GRE tunnel channel: two channels over an in-memory datagram loopback exchange inner IP
    /// packets byte-for-byte (IPv4 and IPv6, picking the GRE protocol type from the version nibble); a garbage datagram
    /// is dropped.
    /// </summary>
    public class GreTunnelChannelTests
    {
        // Minimal buffers whose first nibble selects the family; the channel only inspects the version nibble.
        static byte[] InnerV4(byte tag) => new byte[] { 0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, tag, 0x00 };
        static byte[] InnerV6(byte tag) => new byte[] { 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3A, 0x40, tag, 0x11, 0x22, 0x33 };

        [Fact]
        public async Task InnerIpv4_Sent_On_A_Surfaces_On_B_ByteForByte()
        {
            var link = new LoopbackDatagramLink();
            await using var a = new GreTunnelChannel(link.A, new GreTunnelOptions { Key = 0x12345678, EmitSequenceNumber = true });
            await using var b = new GreTunnelChannel(link.B);

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            b.InboundIpPacket += p => received.TrySetResult(p.ToArray());
            a.Start();
            b.Start();

            byte[] inner = InnerV4(0xAB);
            await a.WriteIpPacketAsync(inner, TestContext.Current.CancellationToken);

            byte[] got = await WithTimeout(received.Task);
            Assert.Equal(inner, got);
        }

        [Fact]
        public async Task InnerIpv6_Sent_On_A_Surfaces_On_B_ByteForByte()
        {
            var link = new LoopbackDatagramLink();
            await using var a = new GreTunnelChannel(link.A, new GreTunnelOptions { EmitChecksum = true });
            await using var b = new GreTunnelChannel(link.B);

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            b.InboundIpPacket += p => received.TrySetResult(p.ToArray());
            a.Start();
            b.Start();

            byte[] inner = InnerV6(0xCD);
            await a.WriteIpPacketAsync(inner, TestContext.Current.CancellationToken);

            byte[] got = await WithTimeout(received.Task);
            Assert.Equal(inner, got);
        }

        [Fact]
        public async Task Garbage_Datagram_Is_Dropped()
        {
            var link = new LoopbackDatagramLink();
            await using var b = new GreTunnelChannel(link.B);

            int count = 0;
            b.InboundIpPacket += _ => Interlocked.Increment(ref count);
            b.Start();

            // A 1-byte datagram is too short for even the GRE base header → TryDecode false → dropped.
            await link.A.SendAsync(new byte[] { 0xFF }, TestContext.Current.CancellationToken);
            // A version-1 (Enhanced GRE) header is also rejected by the standard codec.
            await link.A.SendAsync(new byte[] { 0x00, 0x01, 0x08, 0x00, 0x99 }, TestContext.Current.CancellationToken);
            await Task.Delay(150, TestContext.Current.CancellationToken);

            Assert.Equal(0, count);
        }

        static async Task<T> WithTimeout<T>(Task<T> task)
        {
            Task completed = await Task.WhenAny(task, Task.Delay(5000));
            Assert.Same(task, completed);
            return await task;
        }
    }
}
