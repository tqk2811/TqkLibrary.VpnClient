using System;
using System.Threading.Tasks;
using Xunit;

namespace TqkLibrary.VpnClient.IpEncap.Tests
{
    /// <summary>
    /// Offline coverage for the header-less IPIP/SIT passthrough channel: an inner IPv4 (IPIP, RFC 2003) and an inner
    /// IPv6 (SIT/6in4, RFC 4213) packet round-trip verbatim through an in-memory datagram loopback — the same channel
    /// type serves both families.
    /// </summary>
    public class RawIpPassthroughChannelTests
    {
        static byte[] InnerV4(byte tag) => new byte[] { 0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, tag, 0x77, 0x0A };
        static byte[] InnerV6(byte tag) => new byte[] { 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3A, 0x40, tag, 0x55, 0x66 };

        [Fact]
        public async Task InnerIpv4_RoundTrips_Verbatim()
        {
            byte[] got = await RoundTripAsync(InnerV4(0x42));
            Assert.Equal(InnerV4(0x42), got);
        }

        [Fact]
        public async Task InnerIpv6_RoundTrips_Verbatim()
        {
            byte[] got = await RoundTripAsync(InnerV6(0x84));
            Assert.Equal(InnerV6(0x84), got);
        }

        static async Task<byte[]> RoundTripAsync(byte[] inner)
        {
            var link = new LoopbackDatagramLink();
            await using var a = new RawIpPassthroughChannel(link.A);
            await using var b = new RawIpPassthroughChannel(link.B);

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            b.InboundIpPacket += p => received.TrySetResult(p.ToArray());
            a.Start();
            b.Start();

            await a.WriteIpPacketAsync(inner, TestContext.Current.CancellationToken);

            Task completed = await Task.WhenAny(received.Task, Task.Delay(5000));
            Assert.Same(received.Task, completed);
            return await received.Task;
        }
    }
}
