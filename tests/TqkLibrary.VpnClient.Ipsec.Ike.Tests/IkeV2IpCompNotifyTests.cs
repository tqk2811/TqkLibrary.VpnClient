using TqkLibrary.VpnClient.Ipsec.Ike.V2;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Models;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads;
using TqkLibrary.VpnClient.Ipsec.IpComp.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ike.Tests
{
    /// <summary>
    /// Wire-format + negotiation round-trips for the IKEv2 IPCOMP_SUPPORTED notify (RFC 7296 §3.10.1) that carries the
    /// RFC 3173 IPComp CPI + DEFLATE transform, and the graceful-downgrade selection logic.
    /// </summary>
    public class IkeV2IpCompNotifyTests
    {
        [Fact]
        public void IpCompSupportedNotify_Data_RoundTrips_CpiAndTransform()
        {
            var notify = new IpCompSupportedNotify(0x0102, IpCompTransform.Deflate);
            byte[] data = notify.ToNotifyData();

            Assert.Equal(IpCompSupportedNotify.DataSize, data.Length);
            Assert.Equal(new byte[] { 0x01, 0x02, (byte)IpCompTransform.Deflate }, data); // CPI big-endian ‖ transform ID

            Assert.True(IpCompSupportedNotify.TryParse(data, out IpCompSupportedNotify parsed));
            Assert.Equal((ushort)0x0102, parsed.Cpi);
            Assert.Equal(IpCompTransform.Deflate, parsed.Transform);
        }

        [Fact]
        public void IpCompSupportedNotify_RoundTrips_ThroughAnEncodedIkeMessage()
        {
            // Advertise CPI 2 (well-known DEFLATE) as an IKE Notify, encode into a real IKE_AUTH body, decode, recover.
            NotifyPayload notify = IpCompSupportedNotify.Deflate((ushort)IpCompTransform.Deflate).ToNotifyPayload();

            IkeMessage decoded = RoundTrip(notify);

            NotifyPayload back = decoded.Notifies().Single(n => n.KnownType == IkeNotifyMessageType.IpcompSupported);
            Assert.Equal((ushort)IkeNotifyMessageType.IpcompSupported, back.MessageType);
            Assert.Equal(IkeProtocolId.None, back.ProtocolId); // RFC 7296 §3.10.1: Protocol ID 0
            Assert.Empty(back.Spi);                            //                    SPI Size 0
            Assert.Equal((ushort?)2, IpCompSupportedNotify.FindDeflateCpi(decoded.Notifies()));
        }

        [Fact]
        public void FindDeflateCpi_ReturnsNull_WhenPeerOmitsTheNotify()
        {
            // A response carrying an unrelated notify but no IPCOMP_SUPPORTED → IPComp not active (graceful downgrade).
            IkeMessage decoded = RoundTrip(NotifyPayload.Create(IkeNotifyMessageType.UseTransportMode, Array.Empty<byte>()));
            Assert.Null(IpCompSupportedNotify.FindDeflateCpi(decoded.Notifies()));
        }

        [Fact]
        public void FindDeflateCpi_ReturnsNull_WhenOnlyNonDeflateTransformOffered()
        {
            // A peer that offers IPCOMP_SUPPORTED for LZS (transform 3, not implemented) → we do not activate IPComp.
            NotifyPayload lzs = new IpCompSupportedNotify(0x0100, IpCompTransform.Lzs).ToNotifyPayload();
            IkeMessage decoded = RoundTrip(lzs);
            Assert.Null(IpCompSupportedNotify.FindDeflateCpi(decoded.Notifies()));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(2)]
        public void TryParse_Fails_OnTruncatedData(int length)
        {
            Assert.False(IpCompSupportedNotify.TryParse(new byte[length], out _));
        }

        // Encode the notify inside a real IKE message body and parse it back through the payload chain.
        static IkeMessage RoundTrip(NotifyPayload notify)
        {
            var message = new IkeMessage
            {
                InitiatorSpi = new byte[8],
                ResponderSpi = new byte[8],
                ExchangeType = IkeExchangeType.IkeAuth,
                Flags = IkeHeaderFlags.Initiator,
                MessageId = 1,
            };
            message.Payloads.Add(notify);
            return IkeMessage.Decode(message.Encode());
        }
    }
}
