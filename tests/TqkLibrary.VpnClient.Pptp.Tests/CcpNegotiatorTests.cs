using System;
using System.Collections.Generic;
using TqkLibrary.VpnClient.Crypto.Mppe.Enums;
using TqkLibrary.VpnClient.Ppp;
using TqkLibrary.VpnClient.Ppp.Enums;
using TqkLibrary.VpnClient.Ppp.Models;
using TqkLibrary.VpnClient.Pptp.Ccp;
using TqkLibrary.VpnClient.Pptp.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Pptp.Tests
{
    /// <summary>
    /// Offline coverage for the CCP MPPE negotiator (RFC 1962 + RFC 2118/3078): the MPPE config option codec, the
    /// option-negotiation state machine (reusing <see cref="PppNegotiator"/>), and the strength/stateless outcome.
    /// </summary>
    public class CcpNegotiatorTests
    {
        [Fact]
        public void MppeConfigOption_Encodes_Value_BigEndian_And_RoundTrips()
        {
            var opt = new MppeConfigOption(MppeKeyStrength.Bits128, stateless: true);
            byte[] value = opt.EncodeValue();

            Assert.Equal(4, value.Length);
            // 0x01000000 (stateless) | 0x00000040 (128-bit) = 0x01000040 big-endian.
            Assert.Equal(new byte[] { 0x01, 0x00, 0x00, 0x40 }, value);

            MppeConfigOption back = MppeConfigOption.DecodeValue(value);
            Assert.Equal(MppeKeyStrength.Bits128, back.Strength);
            Assert.True(back.Stateless);
        }

        [Theory]
        [InlineData(MppeKeyStrength.Bits40, 0x00, 0x00, 0x00, 0x20)]
        [InlineData(MppeKeyStrength.Bits56, 0x00, 0x00, 0x00, 0x80)]
        [InlineData(MppeKeyStrength.Bits128, 0x00, 0x00, 0x00, 0x40)]
        public void Strength_Maps_To_Documented_Bits(MppeKeyStrength strength, byte b0, byte b1, byte b2, byte b3)
        {
            var opt = new MppeConfigOption(strength, stateless: false);
            Assert.Equal(new[] { b0, b1, b2, b3 }, opt.EncodeValue());
        }

        [Fact]
        public void Strongest_Bit_Wins_When_Multiple_Offered()
        {
            var opt = new MppeConfigOption(MppeSupportedBits.Encrypt40Bit | MppeSupportedBits.Encrypt128Bit);
            Assert.Equal(MppeKeyStrength.Bits128, opt.Strength);
        }

        [Fact]
        public void Both_Sides_Negotiate_To_128Bit_Stateful()
        {
            var link = new NegotiatorLink();
            var client = new CcpNegotiator(link.A, MppeKeyStrength.Bits128, stateless: false);
            var server = new CcpNegotiator(link.B, MppeKeyStrength.Bits128, stateless: false);
            link.Wire(client, server);

            bool clientOpened = false, serverOpened = false;
            client.Opened += () => clientOpened = true;
            server.Opened += () => serverOpened = true;

            client.Start();
            server.Start();
            link.Pump();

            Assert.True(clientOpened);
            Assert.True(serverOpened);
            Assert.Equal(MppeKeyStrength.Bits128, client.NegotiatedStrength);
            Assert.False(client.NegotiatedStateless);
            Assert.Equal(MppeKeyStrength.Bits128, server.NegotiatedStrength);
        }

        [Fact]
        public void Client_Adopts_Server_Nak_To_Lower_Strength()
        {
            // Client offers 128-bit; server only allows 40-bit → server Naks, client must adopt 40-bit and both open.
            var link = new NegotiatorLink();
            var client = new CcpNegotiator(link.A, MppeKeyStrength.Bits128, stateless: false);
            var server = new CcpNegotiator(link.B, MppeKeyStrength.Bits40, stateless: false);
            link.Wire(client, server);

            bool clientOpened = false, serverOpened = false;
            client.Opened += () => clientOpened = true;
            server.Opened += () => serverOpened = true;

            client.Start();
            server.Start();
            link.Pump();

            Assert.True(clientOpened);
            Assert.True(serverOpened);
            Assert.Equal(MppeKeyStrength.Bits40, client.NegotiatedStrength);
            Assert.Equal(MppeKeyStrength.Bits40, server.NegotiatedStrength);
        }

        [Fact]
        public void Peer_Offering_Multiple_Bits_Is_Naked_To_Strongest()
        {
            var sent = new List<byte[]>();
            var neg = new CcpNegotiator(p => sent.Add(p));

            // Peer offers both 40-bit and 128-bit in one option → must be Naked down to a single (strongest) bit.
            var multi = new MppeConfigOption(MppeSupportedBits.Encrypt40Bit | MppeSupportedBits.Encrypt128Bit);
            byte[] request = PppControlCodec.BuildConfigure((byte)PppCode.ConfigureRequest, 9,
                new[] { new PppOption(MppeConfigOption.OptionType, multi.EncodeValue()) });
            neg.HandlePacket(request);

            byte[] reply = Assert.Single(sent);
            PppControlPacket parsed = PppControlCodec.Parse(reply);
            Assert.Equal((byte)PppCode.ConfigureNak, parsed.Code);
            PppOption nakOption = Assert.Single(PppControlCodec.ParseOptions(parsed.Data));
            MppeConfigOption pinned = MppeConfigOption.DecodeValue(nakOption.Data);
            Assert.Equal(MppeKeyStrength.Bits128, pinned.Strength);
            Assert.Equal(MppeSupportedBits.Encrypt128Bit, pinned.Bits); // exactly one bit
        }

        [Fact]
        public void Peer_Requesting_Unknown_Option_Is_Rejected()
        {
            var sent = new List<byte[]>();
            var neg = new CcpNegotiator(p => sent.Add(p));

            byte[] request = PppControlCodec.BuildConfigure((byte)PppCode.ConfigureRequest, 3,
                new[] { new PppOption(0x01 /* OUI */, new byte[] { 0, 0, 0, 1, 2, 3 }) });
            neg.HandlePacket(request);

            byte[] reply = Assert.Single(sent);
            PppControlPacket parsed = PppControlCodec.Parse(reply);
            Assert.Equal((byte)PppCode.ConfigureReject, parsed.Code);
        }

        [Fact]
        public void Reject_Of_Our_Mppe_Option_Throws_NotSupported()
        {
            var neg = new CcpNegotiator(_ => { });
            neg.Start(); // emit our Configure-Request (id 1)

            byte[] reject = PppControlCodec.BuildConfigure((byte)PppCode.ConfigureReject, 1,
                new[] { new PppOption(MppeConfigOption.OptionType, new MppeConfigOption(MppeKeyStrength.Bits128, false).EncodeValue()) });

            Assert.Throws<NotSupportedException>(() => neg.HandlePacket(reject));
        }

        /// <summary>Wires two negotiators' send callbacks to each other's <see cref="PppNegotiator.HandlePacket"/>.</summary>
        sealed class NegotiatorLink
        {
            readonly Queue<byte[]> _toA = new();
            readonly Queue<byte[]> _toB = new();
            PppNegotiator _a = null!, _b = null!;

            public Action<byte[]> A => p => _toB.Enqueue(p);
            public Action<byte[]> B => p => _toA.Enqueue(p);

            public void Wire(PppNegotiator a, PppNegotiator b) { _a = a; _b = b; }

            public void Pump()
            {
                int guard = 0;
                while ((Deliver(_toA, _a) | Deliver(_toB, _b)) && guard++ < 1000) { }
            }

            static bool Deliver(Queue<byte[]> queue, PppNegotiator target)
            {
                if (queue.Count == 0) return false;
                target.HandlePacket(queue.Dequeue());
                return true;
            }
        }
    }
}
