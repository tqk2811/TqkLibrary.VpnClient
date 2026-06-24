using TqkLibrary.VpnClient.N2n;
using TqkLibrary.VpnClient.N2n.Wire;
using TqkLibrary.VpnClient.N2n.Wire.Enums;
using TqkLibrary.VpnClient.N2n.Wire.Models;
using Xunit;

namespace TqkLibrary.VpnClient.N2n.Tests
{
    /// <summary>
    /// Golden interop KATs captured live against a real n2n v3.1.1 supernode (V.7.4 live lab, community <c>labnet</c>,
    /// cleartext header, transform NULL). These lock byte-compatibility with n2n permanently:
    /// <list type="bullet">
    ///   <item><description>A genuine REGISTER_SUPER produced by the <c>edge</c> binary (decoded here must match the
    ///   fields n2n put on the wire).</description></item>
    ///   <item><description>A genuine REGISTER_SUPER_ACK the supernode sent to this project's harness in reply to our
    ///   own REGISTER_SUPER — the supernode accepted our registration, echoed our cookie, and assigned an address.</description></item>
    /// </list>
    /// All bytes are public wire data from throwaway lab containers (no secrets).
    /// </summary>
    public class N2nInteropKatTests
    {
        readonly N2nPacketCodec _codec = new N2nPacketCodec();

        static byte[] Hex(string h) => Convert.FromHexString(h);

        // Real REGISTER_SUPER (79 bytes) emitted by n2n v3.1.1 `edge -c labnet -A1` (second registration, address known).
        const string GoldenRegisterSuper =
            "030200056c61626e657400000000000000000000000000004" +
            "98a78469e7fb8784aae0ad1ace41834343861356135653436" +
            "353200000000000100105fcbb1627283881f12f497f2203a6c0700000000";

        // Real REGISTER_SUPER_ACK (58 bytes) the supernode sent in reply to OUR harness's REGISTER_SUPER (cookie 037a6c18).
        const string GoldenRegisterSuperAck =
            "030200676c61626e65740000000000000000000000000000037a6c189e9df815e6150ad1acb818000f000089b6ac130006000000000000000000";

        [Fact]
        public void RealRegisterSuper_DecodesToExpectedFields()
        {
            byte[] pkt = Hex(GoldenRegisterSuper);
            Assert.Equal(79, pkt.Length);

            Assert.True(_codec.TryDecodeRegisterSuper(pkt, out var h, out var body));
            Assert.Equal(N2nConstants.PktVersion, h.Version);
            Assert.Equal(N2nConstants.DefaultTtl, h.Ttl);
            Assert.Equal(N2nPacketType.RegisterSuper, h.PacketType);
            Assert.Equal("labnet", h.Community);
            Assert.Equal(N2nFlags.None, h.Flags & N2nFlags.Socket);     // no socket in REGISTER_SUPER here

            Assert.Equal(0x498a7846u, body.Cookie);
            Assert.Equal("9E7FB8784AAE", Convert.ToHexString(body.EdgeMac));
            Assert.Null(body.Sock);
            Assert.Equal(24, body.DevAddr.NetBitLen);                   // bitlen 0x18
            Assert.Equal(N2nAuth.SchemeSimpleId, body.Auth.Scheme);    // scheme 0x0001
            Assert.Equal(16, body.Auth.Token.Length);                  // token_size 0x0010
            Assert.Equal(0u, body.KeyTime);
        }

        [Fact]
        public void RealRegisterSuperAck_DecodesAndEchoesOurCookie()
        {
            byte[] pkt = Hex(GoldenRegisterSuperAck);
            Assert.Equal(58, pkt.Length);

            Assert.True(_codec.TryDecodeRegisterSuperAck(pkt, out var h, out var ack));
            Assert.Equal(N2nPacketType.RegisterSuperAck, h.PacketType);
            Assert.Equal("labnet", h.Community);
            Assert.True((h.Flags & N2nFlags.FromSupernode) != 0);      // supernode-originated
            Assert.True((h.Flags & N2nFlags.Socket) != 0);             // ACK always carries the edge's public socket

            Assert.Equal(0x037a6c18u, ack.Cookie);                     // our harness cookie, echoed back => accepted
            Assert.Equal("9E9DF815E615", Convert.ToHexString(ack.SrcMac)); // supernode MAC
            Assert.Equal(24, ack.DevAddr.NetBitLen);                   // assigned /24
            Assert.Equal(0x0ad1acb8u, ack.DevAddr.NetAddr);            // assigned 10.209.172.184
            Assert.Equal(15, ack.Lifetime);                            // 0x000f
            Assert.Equal("172.19.0.6", ack.Sock.ToEndPoint().Address.ToString()); // ac.13.00.06 -> our edge public IP
        }

        [Fact]
        public void RealRegisterSuper_TypeMismatchRejected()
        {
            // The REGISTER_SUPER bytes are not a REGISTER_SUPER_ACK; the type guard must reject them.
            Assert.False(_codec.TryDecodeRegisterSuperAck(Hex(GoldenRegisterSuper), out _, out _));
        }
    }
}
