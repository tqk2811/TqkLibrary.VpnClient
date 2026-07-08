using System;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.IpEncap.EtherIp;
using Xunit;

namespace TqkLibrary.VpnClient.IpEncap.Tests
{
    /// <summary>
    /// Offline coverage for the EtherIP tunnel channel: two channels over an in-memory datagram loopback exchange a full
    /// Ethernet frame byte-for-byte; a garbage datagram (too short / wrong version) is dropped; and the channel reports the
    /// L2 traits (Ethernet medium, the configured link address, a 14-byte header).
    /// </summary>
    public class EtherIpTunnelChannelTests
    {
        // A minimal but well-formed Ethernet II frame: dst MAC | src MAC | EtherType 0x0800 | 4-byte payload tagged by <paramref name="tag"/>.
        static byte[] Frame(byte tag) => new byte[]
        {
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01,   // dst MAC
            0x02, 0x00, 0x00, 0x00, 0x00, 0x02,   // src MAC
            0x08, 0x00,                           // EtherType IPv4
            0xDE, 0xAD, 0xBE, tag,                // payload
        };

        static readonly byte[] MacA = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x0A };

        [Fact]
        public async Task Frame_Sent_On_A_Surfaces_On_B_ByteForByte()
        {
            var link = new LoopbackDatagramLink();
            await using var a = new EtherIpTunnelChannel(link.A, new EtherIpTunnelOptions { LinkAddress = MacA });
            await using var b = new EtherIpTunnelChannel(link.B);

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            b.InboundFrame += p => received.TrySetResult(p.ToArray());
            a.Start();
            b.Start();

            byte[] frame = Frame(0xAB);
            await a.WriteFrameAsync(frame, TestContext.Current.CancellationToken);

            byte[] got = await WithTimeout(received.Task);
            Assert.Equal(frame, got);
        }

        [Fact]
        public async Task Garbage_Datagram_Is_Dropped()
        {
            var link = new LoopbackDatagramLink();
            await using var b = new EtherIpTunnelChannel(link.B);

            int count = 0;
            b.InboundFrame += _ => Interlocked.Increment(ref count);
            b.Start();

            // A 1-byte datagram is too short for even the EtherIP header → TryDecapsulate false → dropped.
            await link.A.SendAsync(new byte[] { 0xFF }, TestContext.Current.CancellationToken);
            // A wrong-version header (0x40 = version 4) followed by a full frame is rejected too.
            byte[] wrongVersion = new byte[2 + 14];
            wrongVersion[0] = 0x40;
            await link.A.SendAsync(wrongVersion, TestContext.Current.CancellationToken);
            await Task.Delay(150, TestContext.Current.CancellationToken);

            Assert.Equal(0, count);
        }

        [Fact]
        public async Task Channel_Reports_Ethernet_L2_Traits()
        {
            var link = new LoopbackDatagramLink();
            await using var a = new EtherIpTunnelChannel(link.A, new EtherIpTunnelOptions { Mtu = 1300, LinkAddress = MacA });

            Assert.Equal(LinkMedium.Ethernet, a.Medium);
            Assert.Equal(1300, a.Mtu);
            Assert.Equal(EtherIpCodec.EthernetHeaderLength, a.MaxHeaderLength);
            Assert.True(a.RequiresLinkAddressResolution);
            Assert.Equal(MacA, a.LinkAddress.ToArray());
        }

        static async Task<T> WithTimeout<T>(Task<T> task)
        {
            Task completed = await Task.WhenAny(task, Task.Delay(5000));
            Assert.Same(task, completed);
            return await task;
        }
    }
}
