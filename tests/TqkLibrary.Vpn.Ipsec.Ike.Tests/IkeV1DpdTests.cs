using TqkLibrary.Vpn.Ipsec.Ike.V1;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Payloads;
using Xunit;

namespace TqkLibrary.Vpn.Ipsec.Ike.Tests
{
    public class IkeV1DpdTests
    {
        static readonly byte[] CookieI = Bytes(0xA0, 8);
        static readonly byte[] CookieR = Bytes(0xB0, 8);

        [Theory]
        [InlineData(IkeV1Dpd.RUThere)]
        [InlineData(IkeV1Dpd.RUThereAck)]
        public void NotifyBody_RoundTrips_TypeAndSequence(ushort notifyType)
        {
            const uint sequence = 0xDEADBEEF;
            byte[] body = IkeV1Dpd.BuildNotifyBody(CookieI, CookieR, notifyType, sequence);

            Assert.True(IkeV1Dpd.TryParseNotify(body, out ushort parsedType, out uint parsedSequence));
            Assert.Equal(notifyType, parsedType);
            Assert.Equal(sequence, parsedSequence);
        }

        [Fact]
        public void NotifyBody_EmbedsBothCookies_AsTheSpi()
        {
            byte[] body = IkeV1Dpd.BuildNotifyBody(CookieI, CookieR, IkeV1Dpd.RUThere, 1);

            // Layout: DOI(4) | Protocol(1) | SpiSize(1)=16 | NotifyType(2) | SPI(16=CKY-I‖CKY-R) | Data(4).
            Assert.Equal((byte)IkeV1Constants.IpsecDoi, body[3]);
            Assert.Equal(IkeV1Constants.Protocol.Isakmp, body[4]);
            Assert.Equal(16, body[5]);
            Assert.Equal(CookieI, body.AsSpan(8, 8).ToArray());
            Assert.Equal(CookieR, body.AsSpan(16, 8).ToArray());
        }

        [Fact]
        public void TryParseNotify_RejectsNonDpdNotifyTypes()
        {
            byte[] body = IkeV1Dpd.BuildNotifyBody(CookieI, CookieR, 9999, 1);
            Assert.False(IkeV1Dpd.TryParseNotify(body, out _, out _));
        }

        [Fact]
        public void Notification_SurvivesAFullInformationalMessageRoundTrip()
        {
            var message = new IsakmpMessage { ExchangeType = IsakmpExchangeType.Informational, MessageId = 0x11223344 };
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.Hash, new byte[20]));
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.Notification,
                IkeV1Dpd.BuildNotifyBody(CookieI, CookieR, IkeV1Dpd.RUThereAck, 42)));

            IsakmpMessage decoded = IsakmpMessage.Decode(message.Encode());
            IsakmpRawPayload notify = decoded.FindRaw(IsakmpPayloadType.Notification)!;

            Assert.True(IkeV1Dpd.TryParseNotify(notify.Body, out ushort type, out uint sequence));
            Assert.Equal(IkeV1Dpd.RUThereAck, type);
            Assert.Equal(42u, sequence);
        }

        static byte[] Bytes(byte seed, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i);
            return b;
        }
    }
}
