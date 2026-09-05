using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Ipsec.Ike.V1;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Payloads;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ike.Tests
{
    /// <summary>
    /// IKE runs on UDP, so a gateway retransmits earlier messages of an exchange when ours are lost or late. A
    /// retransmitted MM2 reaching the code that reads MM4 used to come out as a bare NullReferenceException from a
    /// null-forgiving <c>!</c>, naming neither the step nor what had arrived — unreadable from a stack trace and
    /// impossible to act on. These pin the two halves of the fix: every step now says what it expected and what it got,
    /// and <see cref="IkeV1Client.CarriesPayload"/> lets the transport tell one Main Mode message from the other before
    /// handing it over (cookies cannot — both belong to the same SA).
    /// </summary>
    public class IkeV1UnexpectedReplyTests
    {
        static readonly byte[] PreSharedKey = { 1, 2, 3, 4 };
        static readonly byte[] CookieI = { 1, 2, 3, 4, 5, 6, 7, 8 };
        static readonly byte[] CookieR = { 9, 10, 11, 12, 13, 14, 15, 16 };

        static IkeV1Client Client() => new(PreSharedKey, IPAddress.Any, IPAddress.Loopback, CookieI);

        static byte[] MainMode(params IsakmpPayload[] payloads)
        {
            var message = new IsakmpMessage
            {
                InitiatorCookie = CookieI,
                ResponderCookie = CookieR,
                ExchangeType = IsakmpExchangeType.MainMode,
                MessageId = 0,
            };
            foreach (IsakmpPayload payload in payloads) message.Payloads.Add(payload);
            return message.Encode();
        }

        // What the gateway sends as MM2: the transform it picked, plus the NAT-T vendor IDs. No key exchange.
        static byte[] MainMode2() => MainMode(
            IkeV1Proposals.Phase1(),
            new IsakmpRawPayload(IsakmpPayloadType.VendorId, IkeV1NatDetection.VendorIdRfc3947));

        [Fact]
        public void A_retransmitted_MM2_arriving_where_MM4_is_expected_says_so()
        {
            IkeV1Client client = Client();

            VpnServerRejectedException ex = Assert.Throws<VpnServerRejectedException>(
                () => client.ProcessMainMode4(MainMode2()));

            Assert.Contains("MM4", ex.Message);
            Assert.Contains("KeyExchange", ex.Message);
            // The message has to carry what DID arrive, or it explains nothing.
            Assert.Contains("SecurityAssociation", ex.Message);
        }

        [Fact]
        public void An_MM4_without_a_nonce_says_which_payload_is_missing()
        {
            IkeV1Client client = Client();
            byte[] keOnly = MainMode(new IsakmpRawPayload(IsakmpPayloadType.KeyExchange, new byte[128]));

            VpnServerRejectedException ex = Assert.Throws<VpnServerRejectedException>(
                () => client.ProcessMainMode4(keOnly));

            Assert.Contains("Nonce", ex.Message);
        }

        [Fact]
        public void A_reply_naming_no_transform_is_reported_rather_than_indexed_into()
        {
            IkeV1Client client = Client();
            // An SA payload with no proposal at all: the old code read Proposals[0] straight away.
            byte[] emptySa = MainMode(new IsakmpSaPayload());

            VpnServerRejectedException ex = Assert.Throws<VpnServerRejectedException>(
                () => client.ProcessMainMode2(emptySa));

            Assert.Contains("MM2", ex.Message);
        }

        [Fact]
        public void A_reply_with_no_SA_at_all_is_reported_at_MM2()
        {
            IkeV1Client client = Client();
            byte[] vendorIdOnly = MainMode(
                new IsakmpRawPayload(IsakmpPayloadType.VendorId, IkeV1NatDetection.VendorIdRfc3947));

            Assert.Throws<VpnServerRejectedException>(() => client.ProcessMainMode2(vendorIdOnly));
        }

        // This is what the transport waits on: MM2 and MM4 share both cookies, so only the payloads tell them apart.
        [Fact]
        public void MM2_and_MM4_are_told_apart_by_the_payload_they_carry()
        {
            byte[] mm2 = MainMode2();
            byte[] mm4 = MainMode(
                new IsakmpRawPayload(IsakmpPayloadType.KeyExchange, new byte[128]),
                new IsakmpRawPayload(IsakmpPayloadType.Nonce, new byte[16]));

            Assert.True(IkeV1Client.CarriesPayload(mm2, IsakmpPayloadType.SecurityAssociation));
            Assert.False(IkeV1Client.CarriesPayload(mm2, IsakmpPayloadType.KeyExchange));

            Assert.True(IkeV1Client.CarriesPayload(mm4, IsakmpPayloadType.KeyExchange));
            Assert.False(IkeV1Client.CarriesPayload(mm4, IsakmpPayloadType.SecurityAssociation));
        }

        // A datagram that cannot be parsed is not the reply either — saying "no" keeps the exchange waiting for the
        // real one instead of failing on rubbish that happened to reach the socket.
        [Theory]
        [InlineData(0)]
        [InlineData(4)]
        [InlineData(27)]   // one byte short of an ISAKMP header
        public void A_datagram_too_short_to_be_a_message_carries_nothing(int length)
            => Assert.False(IkeV1Client.CarriesPayload(new byte[length], IsakmpPayloadType.KeyExchange));

        [Fact]
        public void Junk_the_length_of_a_message_carries_nothing()
        {
            var junk = new byte[64];
            for (int i = 0; i < junk.Length; i++) junk[i] = (byte)(i * 7);

            Assert.False(IkeV1Client.CarriesPayload(junk, IsakmpPayloadType.KeyExchange));
        }
    }
}
