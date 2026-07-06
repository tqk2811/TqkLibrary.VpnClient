using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.GtpU.Tests
{
    /// <summary>
    /// Offline coverage for the GTP-U (3GPP TS 29.281) static-mode driver runtime: the GTP-U header codec
    /// (<see cref="GtpUHeader"/>) and the reused IpEncap passthrough data plane over a UDP datagram pipe framed with the
    /// G-PDU header. No admin/server, no <c>Integration</c> trait — the real-socket case uses 127.0.0.1 ephemeral ports, the
    /// others an in-memory loopback link. Covers: G-PDU header round-trip (version/PT/E/S/PN flags, message type 255, Length
    /// field, 32-bit big-endian TEID, optional Sequence Number block); skip extension headers; parse-but-not-deliver Echo /
    /// Error Indication; reject non-version-1 / runt / length-too-long / truncated or zero-length extension; inner-IP
    /// passthrough both directions over the loopback link (IPv4/IPv6, with and without sequence numbers); receiver drops
    /// Echo/Error-Indication + wrong-TEID then delivers a valid G-PDU; a real UDP loopback round-trip; driver capabilities
    /// (no elevation / no raw socket) and default options.
    /// </summary>
    public class GtpUTests
    {
        const string ServerHost = "203.0.113.9"; // TEST-NET-3 literal so the resolver returns it verbatim (no DNS)
        const uint Teid = 0xDEADBEEF;

        // ---- 1) GTP-U header codec: encode → decode round-trip ----

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void GtpUHeader_Encode_ThenDecode_RoundTripsGPdu(bool withSequence)
        {
            byte[] payload = { 0x45, 0x00, 0x00, 0x14, 0xDE, 0xAD, 0xBE, 0xEF };
            ushort? sequence = withSequence ? (ushort)0x1234 : (ushort?)null;
            byte[] datagram = GtpUHeader.Encode(Teid, payload, sequence);

            // Byte 0: Version=1 (top 3 bits) + PT=1 (0x10); S set (0x02) only when a sequence number is supplied.
            byte expectedFlags = (byte)(0x30 | (withSequence ? 0x02 : 0x00));
            Assert.Equal(expectedFlags, datagram[0]);
            Assert.Equal(GtpUHeader.MessageTypeGPdu, datagram[1]);

            // Length field = octets after the mandatory 8-byte header (optional block + payload).
            int expectedLength = (withSequence ? GtpUHeader.OptionalBlockLength : 0) + payload.Length;
            Assert.Equal(expectedLength, (datagram[2] << 8) | datagram[3]);
            Assert.Equal(GtpUHeader.BaseLength + expectedLength, datagram.Length);

            // TEID is 32-bit big-endian in bytes 4-7.
            Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, datagram.AsSpan(4, 4).ToArray());

            Assert.True(GtpUHeader.TryDecode(datagram, out GtpUHeader header));
            Assert.True(header.IsGPdu);
            Assert.Equal(Teid, header.Teid);
            Assert.Equal(withSequence, header.HasSequence);
            if (withSequence) Assert.Equal((ushort)0x1234, header.SequenceNumber);
            Assert.Equal(payload, datagram.AsSpan(header.PayloadOffset, header.PayloadLength).ToArray());
        }

        [Fact]
        public void GtpUHeader_Encode_WritesTeid32BitBigEndian()
        {
            byte[] datagram = GtpUHeader.Encode(0x01020304, new byte[] { 0x60 });
            Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, datagram.AsSpan(4, 4).ToArray());
            Assert.True(GtpUHeader.TryDecode(datagram, out GtpUHeader header));
            Assert.Equal(0x01020304u, header.Teid);
        }

        [Fact]
        public void GtpUHeader_Encode_WithSequence_SetsSFlagAndOptionalBlock()
        {
            byte[] payload = { 0x45, 0x11 };
            byte[] datagram = GtpUHeader.Encode(Teid, payload, 0xABCD);

            Assert.Equal(0x02, datagram[0] & 0x02);                 // S flag set
            Assert.Equal(0x00, datagram[0] & 0x04);                 // E flag not set
            Assert.Equal(0xAB, datagram[GtpUHeader.BaseLength]);     // Sequence Number high byte
            Assert.Equal(0xCD, datagram[GtpUHeader.BaseLength + 1]); // Sequence Number low byte
            Assert.Equal(0x00, datagram[GtpUHeader.BaseLength + 2]); // N-PDU Number
            Assert.Equal(0x00, datagram[GtpUHeader.BaseLength + 3]); // Next Extension Header Type
            Assert.Equal(payload, datagram.AsSpan(GtpUHeader.BaseLength + GtpUHeader.OptionalBlockLength).ToArray());
        }

        // ---- 2) skip extension headers (1+), then the payload ----

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        public void GtpUHeader_Decode_SkipsExtensionHeaders(int extensionCount)
        {
            byte[] payload = { 0x45, 0x00, 0x00, 0x14 };
            byte[] datagram = BuildGPduWithExtensions(Teid, payload, extensionCount);

            Assert.True(GtpUHeader.TryDecode(datagram, out GtpUHeader header));
            Assert.True(header.IsGPdu);
            Assert.Equal(Teid, header.Teid);
            // Payload begins after the mandatory header + optional block + extensionCount * 4-byte extension headers.
            Assert.Equal(GtpUHeader.BaseLength + GtpUHeader.OptionalBlockLength + extensionCount * 4, header.PayloadOffset);
            Assert.Equal(payload, datagram.AsSpan(header.PayloadOffset, header.PayloadLength).ToArray());
        }

        // ---- 3) control messages parse but are not G-PDUs ----

        [Theory]
        [InlineData(GtpUHeader.MessageTypeEchoRequest)]
        [InlineData(GtpUHeader.MessageTypeEchoResponse)]
        [InlineData(GtpUHeader.MessageTypeErrorIndication)]
        public void GtpUHeader_Decode_ParsesControlMessage_ButNotGPdu(byte messageType)
        {
            byte[] datagram = { 0x30, messageType, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            Assert.True(GtpUHeader.TryDecode(datagram, out GtpUHeader header));
            Assert.False(header.IsGPdu);
            Assert.Equal(messageType, header.MessageType);
        }

        // ---- 4) reject malformed datagrams ----

        [Theory]
        [InlineData(0)] // version 0
        [InlineData(2)] // version 2
        [InlineData(3)] // version 3
        public void GtpUHeader_Decode_RejectsNonVersion1(int version)
        {
            byte[] datagram = new byte[GtpUHeader.BaseLength];
            datagram[0] = (byte)((version << 5) | 0x10); // PT set, given version in top 3 bits
            datagram[1] = GtpUHeader.MessageTypeGPdu;
            Assert.False(GtpUHeader.TryDecode(datagram, out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(4)]
        [InlineData(7)]
        public void GtpUHeader_Decode_RejectsRunt(int length)
        {
            byte[] datagram = new byte[length];
            if (length > 0) datagram[0] = 0x30; // version 1 + PT — still too short
            Assert.False(GtpUHeader.TryDecode(datagram, out _));
        }

        [Fact]
        public void GtpUHeader_Decode_RejectsLengthFieldTooLong()
        {
            // Length field declares 100 octets after the header, but only the 8-byte header is present.
            byte[] datagram = { 0x30, GtpUHeader.MessageTypeGPdu, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00 };
            Assert.False(GtpUHeader.TryDecode(datagram, out _));
        }

        [Fact]
        public void GtpUHeader_Decode_RejectsTruncatedExtension()
        {
            // E flag set, optional block declares a first extension type, but the extension claims 16 bytes with none present.
            byte[] datagram =
            {
                0x34, GtpUHeader.MessageTypeGPdu, 0x00, 0x05,       // E flag, Length=5 (optional 4 + 1 ext-length byte)
                0x00, 0x00, 0x00, 0x00,                            // TEID
                0x00, 0x00, 0x00, 0xC0,                            // optional block, next-ext-type = 0xC0
                0x04,                                              // extension length = 4 units = 16 bytes (truncated)
            };
            Assert.False(GtpUHeader.TryDecode(datagram, out _));
        }

        [Fact]
        public void GtpUHeader_Decode_RejectsZeroLengthExtension()
        {
            // A 0-length extension header would never terminate the chain — reject it.
            byte[] datagram =
            {
                0x34, GtpUHeader.MessageTypeGPdu, 0x00, 0x05,       // E flag, Length=5
                0x00, 0x00, 0x00, 0x00,                            // TEID
                0x00, 0x00, 0x00, 0xC0,                            // optional block, next-ext-type = 0xC0
                0x00,                                              // extension length = 0 → malformed
            };
            Assert.False(GtpUHeader.TryDecode(datagram, out _));
        }

        // ---- 5) inner-IP passthrough both directions over the in-memory loopback link ----

        [Theory]
        [InlineData(false, false)]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(true, true)]
        public async Task Tunnel_RoundTrips_InnerPacket(bool innerIsIpv6, bool enableSequence)
        {
            var link = new LoopbackDatagramLink();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var options = new GtpUOptions { Teid = Teid, EnableSequence = enableSequence, Mtu = 1400 };

            var driverA = new GtpUDriver(options, transportFactory: new FakeGtpUTransportFactory(link.A));
            var driverB = new GtpUDriver(options, transportFactory: new FakeGtpUTransportFactory(link.B));
            await using IVpnConnection connA = await driverA.ConnectAsync(new VpnEndpoint(ServerHost, 0), new VpnCredentials(), cts.Token);
            await using IVpnConnection connB = await driverB.ConnectAsync(new VpnEndpoint(ServerHost, 0), new VpnCredentials(), cts.Token);
            IPacketChannel chA = connA.Sessions[0].PacketChannel;
            IPacketChannel chB = connB.Sessions[0].PacketChannel;

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            chB.InboundIpPacket += p => received.TrySetResult(p.ToArray());

            byte[] inner = innerIsIpv6 ? BuildIpv6Packet(0xCD) : BuildIpv4Packet(0xAB);
            await chA.WriteIpPacketAsync(inner, cts.Token);

            Assert.Equal(inner, await WaitAsync(received.Task, cts.Token));
        }

        // ---- 6) receiver drops Echo / Error Indication, then delivers a valid G-PDU ----

        [Fact]
        public async Task Receiver_DropsControlMessages_ThenDeliversGPdu()
        {
            var link = new LoopbackDatagramLink();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var options = new GtpUOptions { Teid = Teid, Mtu = 1400 };

            var driver = new GtpUDriver(options, transportFactory: new FakeGtpUTransportFactory(link.B));
            await using IVpnConnection conn = await driver.ConnectAsync(new VpnEndpoint(ServerHost, 0), new VpnCredentials(), cts.Token);
            IPacketChannel channel = conn.Sessions[0].PacketChannel;

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            channel.InboundIpPacket += p => received.TrySetResult(p.ToArray());

            // Echo Request (type 1) and Error Indication (type 26) must be dropped (not user data).
            await link.A.SendAsync(new byte[] { 0x30, GtpUHeader.MessageTypeEchoRequest, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, cts.Token);
            await link.A.SendAsync(new byte[] { 0x30, GtpUHeader.MessageTypeErrorIndication, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, cts.Token);
            // Then a valid G-PDU → must surface the inner IPv4 packet, proving the receive loop continued.
            byte[] inner = BuildIpv4Packet(0x5A);
            await link.A.SendAsync(GtpUHeader.Encode(Teid, inner), cts.Token);

            Assert.Equal(inner, await WaitAsync(received.Task, cts.Token));
        }

        // ---- 7) receiver drops a G-PDU whose TEID does not match the configured expected inbound TEID ----

        [Fact]
        public async Task Receiver_DropsWrongInboundTeid_ThenDeliversMatching()
        {
            var link = new LoopbackDatagramLink();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var options = new GtpUOptions { Teid = Teid, ExpectedInboundTeid = 0x11111111, Mtu = 1400 };

            var driver = new GtpUDriver(options, transportFactory: new FakeGtpUTransportFactory(link.B));
            await using IVpnConnection conn = await driver.ConnectAsync(new VpnEndpoint(ServerHost, 0), new VpnCredentials(), cts.Token);
            IPacketChannel channel = conn.Sessions[0].PacketChannel;

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            channel.InboundIpPacket += p => received.TrySetResult(p.ToArray());

            byte[] inner = BuildIpv4Packet(0x77);
            await link.A.SendAsync(GtpUHeader.Encode(0x22222222, inner), cts.Token); // wrong TEID → dropped
            await link.A.SendAsync(GtpUHeader.Encode(0x11111111, inner), cts.Token); // matching TEID → delivered

            Assert.Equal(inner, await WaitAsync(received.Task, cts.Token));
        }

        // ---- 8) real UDP loopback: GTP-U client <-> a raw UDP reflecting peer on 127.0.0.1 ----

        [Fact]
        public async Task Udp_Loopback_GtpU_RoundTrips_InnerIpv4OverRealSocket()
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

            using var peer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            peer.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            int peerPort = ((IPEndPoint)peer.LocalEndPoint!).Port;
            var peerLoop = Task.Run(() => RunEchoPeerAsync(peer, cts.Token));

            // The peer reflects the whole G-PDU verbatim; the client's framing decodes it and surfaces the inner IP packet.
            var options = new GtpUOptions { Port = peerPort, Teid = Teid };
            var driver = new GtpUDriver(options, transportFactory: new GtpUUdpTransportFactory(IPAddress.Loopback));
            await using IVpnConnection conn = await driver.ConnectAsync(new VpnEndpoint("127.0.0.1", 0), new VpnCredentials(), cts.Token);
            IPacketChannel channel = conn.Sessions[0].PacketChannel;

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            channel.InboundIpPacket += p => received.TrySetResult(p.ToArray());

            byte[] inner = BuildIpv4Packet(0x11);
            await channel.WriteIpPacketAsync(inner, cts.Token);

            Assert.Equal(inner, await WaitAsync(received.Task, cts.Token));

            cts.Cancel();
            try { await peerLoop; } catch { }
        }

        // A raw UDP peer that reflects every datagram back to the sender's source endpoint.
        static async Task RunEchoPeerAsync(Socket peer, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[2048];
            var any = new IPEndPoint(IPAddress.Loopback, 0);
            using (cancellationToken.Register(() => { try { peer.Dispose(); } catch { } }))
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    SocketReceiveFromResult r = await peer.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, any).ConfigureAwait(false);
                    if (r.ReceivedBytes <= 0) continue;
                    await peer.SendToAsync(new ArraySegment<byte>(buffer, 0, r.ReceivedBytes), SocketFlags.None, r.RemoteEndPoint).ConfigureAwait(false);
                }
            }
        }

        // ---- 9) driver capabilities + default options + null-guard ----

        [Fact]
        public void Driver_ExposesGtpUCapabilities()
        {
            var driver = new GtpUDriver();

            Assert.Equal("gtpu", driver.Name);
            Assert.False(driver.Capabilities.UsesPpp);
            Assert.False(driver.Capabilities.RequiresElevation);
            Assert.False(driver.Capabilities.RequiresRawIpSocket);
            Assert.Equal(VpnLinkLayer.L3Ip, driver.Capabilities.LinkLayer);
            Assert.True((driver.Capabilities.TransportKinds & VpnTransportKind.Udp) != 0);
            Assert.Equal(VpnSecurityKind.None, driver.Capabilities.SecurityKinds);
            Assert.Equal(VpnAuthMethod.None, driver.Capabilities.AuthMethods);
            Assert.Equal(AddressAssignment.OutOfBand, driver.Capabilities.AddressAssignment);
        }

        [Fact]
        public void Options_Defaults_ArePort2152NoSequence()
        {
            var options = new GtpUOptions();
            Assert.Equal(2152, options.Port);
            Assert.Equal(0u, options.Teid);
            Assert.Null(options.ExpectedInboundTeid);
            Assert.False(options.EnableSequence);
            Assert.Equal(1400, options.Mtu);
        }

        [Fact]
        public void Connection_NullTransportFactory_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new GtpUConnection(ServerHost, null!));
        }

        // ---- helpers ----

        // Builds a G-PDU with the E flag set, an optional block whose Next-Extension-Header-Type names the first extension,
        // and `extensionCount` minimal 4-byte extension headers (each 1 unit long), then the payload.
        static byte[] BuildGPduWithExtensions(uint teid, byte[] payload, int extensionCount)
        {
            const byte extType = 0xC0;
            int extBytes = extensionCount * 4;
            int lengthAfterHeader = GtpUHeader.OptionalBlockLength + extBytes + payload.Length;
            byte[] d = new byte[GtpUHeader.BaseLength + lengthAfterHeader];

            d[0] = 0x34; // Version 1 + PT + E flag
            d[1] = GtpUHeader.MessageTypeGPdu;
            d[2] = (byte)(lengthAfterHeader >> 8);
            d[3] = (byte)lengthAfterHeader;
            d[4] = (byte)(teid >> 24);
            d[5] = (byte)(teid >> 16);
            d[6] = (byte)(teid >> 8);
            d[7] = (byte)teid;

            // optional block: seq(2)=0, npdu(1)=0, next-ext-type(1)=extType
            d[11] = extType;

            int p = GtpUHeader.BaseLength + GtpUHeader.OptionalBlockLength;
            for (int i = 0; i < extensionCount; i++)
            {
                d[p] = 1;          // extension length = 1 unit = 4 bytes
                d[p + 1] = 0xAB;   // content
                d[p + 2] = 0xCD;   // content
                d[p + 3] = i == extensionCount - 1 ? (byte)0 : extType; // next-ext-type; last one terminates the chain
                p += 4;
            }
            payload.CopyTo(d, p);
            return d;
        }

        // A minimal but version-correct IPv4 packet (first nibble 4).
        static byte[] BuildIpv4Packet(byte marker)
        {
            byte[] p = new byte[20];
            p[0] = 0x45; // version 4, IHL 5
            p[9] = 0xFE; // some protocol
            p[19] = marker;
            return p;
        }

        // A minimal IPv6 packet (first nibble 6).
        static byte[] BuildIpv6Packet(byte marker)
        {
            byte[] p = new byte[40];
            p[0] = 0x60; // version 6
            p[39] = marker;
            return p;
        }

        static async Task<T> WaitAsync<T>(Task<T> task, CancellationToken cancellationToken)
        {
            var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (cancellationToken.Register(() => cancelled.TrySetResult(true)))
            {
                if (await Task.WhenAny(task, cancelled.Task).ConfigureAwait(false) != task)
                    cancellationToken.ThrowIfCancellationRequested();
                return await task.ConfigureAwait(false);
            }
        }

        /// <summary>A fake <see cref="IGtpUTransportFactory"/> handing out one preconfigured loopback datagram end as the UDP pipe.</summary>
        sealed class FakeGtpUTransportFactory : IGtpUTransportFactory
        {
            readonly IDatagramTransport _transport;
            public FakeGtpUTransportFactory(IDatagramTransport transport) => _transport = transport;
            public IDatagramTransport Create(IPEndPoint remote) => _transport;
        }
    }
}
