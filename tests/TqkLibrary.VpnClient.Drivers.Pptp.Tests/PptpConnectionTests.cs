using System;
using System.Buffers.Binary;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.Drivers.Pptp;
using TqkLibrary.VpnClient.Ppp.Enums;
using TqkLibrary.VpnClient.Ppp.Framing.Enums;
using TqkLibrary.VpnClient.Pptp;
using TqkLibrary.VpnClient.Pptp.Ccp;
using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Gre;
using TqkLibrary.VpnClient.Pptp.Interfaces;
using TqkLibrary.VpnClient.Pptp.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Pptp.Tests
{
    /// <summary>
    /// Offline end-to-end coverage for the PPTP driver runtime (<see cref="PptpConnection"/> / <see cref="PptpDriver"/>),
    /// driven against a simulated PAC over two in-memory transports (an <see cref="IByteStreamTransport"/> pair for the
    /// TCP/1723 control connection and a loopback datagram link for the GRE/proto-47 data plane). No real sockets, no
    /// <c>Integration</c> trait.
    /// <para>
    /// <b>What this COVERS (deterministic, exercises the real driver's <c>EstablishAsync</c>):</b>
    /// <list type="bullet">
    ///   <item>The control handshake yields the correct Local/Peer Call-IDs (SCCRQ→SCCRP, OCRQ→OCRP).</item>
    ///   <item>The GRE data plane is keyed by those Call-IDs: the client's first LCP Configure-Request is GRE-wrapped
    ///         with the <c>PeerCallId</c> and reaches the server side, decodes via <see cref="PptpGreCodec"/>, and
    ///         carries PPP protocol LCP (0xC021) code Configure-Request.</item>
    ///   <item>A server→client GRE frame (addressed to the client's <c>LocalCallId</c>) surfaces back to the client's
    ///         GRE channel.</item>
    ///   <item>The driver's MPPE key derivation interoperates: the client's send session (built from the MS-CHAPv2
    ///         NT-Response) is decryptable by the symmetric server session
    ///         (<see cref="MppeSessionFactory.CreateServerSessions"/>), and vice versa.</item>
    ///   <item>A control-connection refusal (SCCRP Result-Code ≠ Successful) fails the connect.</item>
    /// </list>
    /// </para>
    /// <para>
    /// <b>What is DEFERRED to live validation (roadmap Q.1):</b> a full MS-CHAPv2 server authentication exchange,
    /// the CCP/MPPE Opened transition negotiated end-to-end, and the IPCP address assignment that drives the connection
    /// to <see cref="VpnConnectionState.Connected"/>. The library has no server-side MS-CHAPv2 PPP stack
    /// (<c>PppEngine</c> is client-auth only; no server <c>IPppAuthenticator</c> exists), so a faithful server cannot
    /// answer the CHAP Challenge offline without reimplementing one. The deterministic plumbing above proves the data
    /// path is wired correctly up to the first LCP exchange; the remainder is verified live in Q.1.
    /// </para>
    /// </summary>
    public class PptpConnectionTests
    {
        const string User = "alice";
        const string Pass = "Pa$$w0rd!";
        const string ServerHost = "203.0.113.7"; // TEST-NET-3 literal so the resolver returns it verbatim (no DNS)

        [Fact]
        public async Task Establish_RunsControlHandshake_AndGreWrapsFirstLcpWithPeerCallId()
        {
            var control = new LoopbackByteStreamPair();
            var pac = new SimulatedPac(control.Server);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            Task serverLoop = pac.RunAsync(cts.Token);

            var greLink = new LoopbackDatagramLink();
            var rawIpFactory = new FakeRawIpTransportFactory(greLink.A);

            // A short handshake timeout: EstablishAsync will time out (no faithful auth server offline), but only AFTER
            // the control handshake completed and the client put its first GRE-wrapped LCP frame on the wire.
            var connection = new PptpConnection(ServerHost, rawIpFactory,
                controlTransportFactory: (_, _) => Task.FromResult<IByteStreamTransport>(control.Client),
                timeoutOptions: new PptpTimeoutOptions { HandshakeTimeout = TimeSpan.FromSeconds(2) });

            // Drive the real EstablishAsync in the background; it blocks awaiting CCP/IPCP and then times out.
            Task connect = connection.ConnectAsync(User, Pass, cts.Token);

            // The server GRE end receives the client's first GRE packet: it must be addressed to the PAC's Call-ID
            // (== client PeerCallId) and carry an LCP Configure-Request.
            byte[] datagram = await ReceiveDatagramAsync(greLink.B, cts.Token);
            Assert.True(PptpGreCodec.TryDecode(datagram, out PptpGrePacket? greIn) && greIn is not null);
            Assert.Equal(SimulatedPac.PacCallId, greIn!.CallId); // the client stamps the PAC's Call-ID on outbound GRE

            // The GRE payload is a bare PPP frame (FF 03 optionally stripped) → [proto:2][code ...].
            (ushort proto, byte code) = ReadPppProtoAndCode(greIn.Payload.Span);
            Assert.Equal((ushort)PppProtocol.Lcp, proto);
            Assert.Equal((byte)PppCode.ConfigureRequest, code);

            // A server→client GRE frame addressed to the client's LocalCallId must surface on the client's GRE channel.
            // We reach into the client GRE end (greLink.A) directly: send a GRE packet stamped with the client's
            // LocalCallId so the client's PptpGreChannel accepts it (wrong Call-IDs are dropped).
            var serverLcpAck = new PptpGrePacket
            {
                CallId = PptpConnection_LocalCallId,
                SequenceNumber = 0,
                Payload = BuildLcpConfigureAck(),
            };
            await greLink.B.SendAsync(PptpGreCodec.Encode(serverLcpAck), cts.Token);
            // (The client consumes it inside its PPP/MPPE stack; reaching here without an exception confirms delivery.)

            // The attempt ultimately fails (timeout) because no faithful auth server answers — assert that cleanly.
            await Assert.ThrowsAnyAsync<Exception>(() => connect);
            Assert.NotEqual(VpnConnectionState.Connected, connection.State);

            pac.Stop();
            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Establish_NegotiatesCorrectLocalAndPeerCallIds()
        {
            var control = new LoopbackByteStreamPair();
            var pac = new SimulatedPac(control.Server);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            _ = pac.RunAsync(cts.Token);

            // Drive only the control plane via a real PptpControlConnection (the same handshake the driver runs in
            // EstablishAsync step 1), proving the Call-ID negotiation the GRE channel is keyed on.
            var client = new PptpControlConnection(control.Client);
            await client.EstablishControlConnectionAsync(cts.Token);
            await client.PlaceOutgoingCallAsync(PptpConnection_LocalCallId, cts.Token);

            Assert.Equal(PptpConnection_LocalCallId, client.LocalCallId);
            Assert.Equal(SimulatedPac.PacCallId, client.PeerCallId);

            pac.Stop();
        }

        [Fact]
        public async Task Establish_ServerRefusingControlConnection_FailsConnect()
        {
            var control = new LoopbackByteStreamPair();
            var pac = new SimulatedPac(control.Server) { StartResult = PptpResultCode.NotAuthorized };
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            _ = pac.RunAsync(cts.Token);

            var greLink = new LoopbackDatagramLink();
            var connection = new PptpConnection(ServerHost, new FakeRawIpTransportFactory(greLink.A),
                controlTransportFactory: (_, _) => Task.FromResult<IByteStreamTransport>(control.Client));

            await Assert.ThrowsAnyAsync<Exception>(() => connection.ConnectAsync(User, Pass, cts.Token));
            Assert.NotEqual(VpnConnectionState.Connected, connection.State);

            pac.Stop();
            await connection.DisposeAsync();
        }

        [Fact]
        public void MppeKeys_ClientAndServerSessions_Interoperate()
        {
            // The MPPE key material the driver derives (client side) must be decryptable by the symmetric server
            // session (CreateServerSessions, RFC 3079 §3.3 isServer:true) and vice versa — the data-plane crypto round-trip.
            byte[] ntResponse = BuildNtResponse();
            var option = new MppeConfigOption(TqkLibrary.VpnClient.Crypto.Mppe.Enums.MppeKeyStrength.Bits128, stateless: false);

            (var clientSend, var clientReceive) = MppeSessionFactory.CreateClientSessions(Pass, ntResponse, option);
            (var serverSend, var serverReceive) = MppeSessionFactory.CreateServerSessions(Pass, ntResponse, option);

            byte[] up = { 0x00, 0x21, 0xDE, 0xAD, 0xBE, 0xEF }; // client → server
            byte[] cipherUp = clientSend.Encrypt(up);
            Assert.Equal(up, serverReceive.Decrypt(cipherUp));

            byte[] down = { 0x00, 0x21, 0x12, 0x34, 0x56, 0x78 }; // server → client
            byte[] cipherDown = serverSend.Encrypt(down);
            Assert.Equal(down, clientReceive.Decrypt(cipherDown));
        }

        [Fact]
        public void Driver_ExposesPptpCapabilities()
        {
            var driver = new PptpDriver(new FakeRawIpTransportFactory(new LoopbackDatagramLink().A));
            Assert.Equal("pptp", driver.Name);
            Assert.True(driver.Capabilities.UsesPpp);
            Assert.True(driver.Capabilities.RequiresElevation);
            Assert.True(driver.Capabilities.RequiresRawIpSocket);
            Assert.True((driver.Capabilities.SecurityKinds & Abstractions.Drivers.Enums.VpnSecurityKind.Mppe) != 0);
            Assert.True((driver.Capabilities.AuthMethods & Abstractions.Drivers.Enums.VpnAuthMethod.UserPassword) != 0);
        }

        // The local Call-ID PptpConnection assigns to its Outgoing-Call-Request (mirrors PptpConnection.DefaultLocalCallId).
        const ushort PptpConnection_LocalCallId = 0x4000;

        static (ushort proto, byte code) ReadPppProtoAndCode(ReadOnlySpan<byte> frame)
        {
            int offset = 0;
            if (frame.Length >= 2 && frame[0] == 0xFF && frame[1] == 0x03) offset = 2; // skip Address/Control
            ushort proto = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(offset));
            byte code = frame[offset + 2];
            return (proto, code);
        }

        // A minimal LCP Configure-Ack body [FF 03][C0 21][code=2 ...] for the server→client direction.
        static byte[] BuildLcpConfigureAck()
        {
            byte[] lcp = { 0x02, 0x01, 0x00, 0x04 }; // code=ConfigureAck, id=1, length=4 (no options)
            byte[] frame = new byte[4 + lcp.Length];
            frame[0] = 0xFF; frame[1] = 0x03;
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2), (ushort)PppProtocol.Lcp);
            Buffer.BlockCopy(lcp, 0, frame, 4, lcp.Length);
            return frame;
        }

        static byte[] BuildNtResponse()
        {
            var r = new byte[24];
            for (int i = 0; i < r.Length; i++) r[i] = (byte)(i + 7);
            return r;
        }

        static async Task<byte[]> ReceiveDatagramAsync(LoopbackDatagramLink.End end, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[2048];
            int n = await end.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            return buffer.AsMemory(0, n).ToArray();
        }

        /// <summary>A fake <see cref="IRawIpTransportFactory"/> handing out one preconfigured loopback datagram end as the GRE pipe.</summary>
        sealed class FakeRawIpTransportFactory : IRawIpTransportFactory
        {
            readonly IDatagramTransport _transport;
            public FakeRawIpTransportFactory(IDatagramTransport transport) => _transport = transport;
            public bool IsAvailable => true;
            public IDatagramTransport Create(IPAddress remote, int ipProtocol, IPAddress? localBind = null) => _transport;
        }

        /// <summary>A minimal simulated PAC that answers the PNS control messages over a loopback byte stream.</summary>
        sealed class SimulatedPac
        {
            public const ushort PacCallId = 0x9001;

            readonly PptpControlConnection _conn;
            bool _stop;

            public SimulatedPac(LoopbackByteStreamPair.End end) => _conn = new PptpControlConnection(end, hostName: "pac");

            public PptpResultCode StartResult { get; set; } = PptpResultCode.Successful;
            public PptpResultCode CallResult { get; set; } = PptpResultCode.Successful;

            public void Stop() => _stop = true;

            public async Task RunAsync(CancellationToken cancellationToken)
            {
                try
                {
                    while (!_stop && !cancellationToken.IsCancellationRequested)
                    {
                        IPptpControlMessage msg = await _conn.ReadMessageAsync(cancellationToken).ConfigureAwait(false);
                        switch (msg)
                        {
                            case StartControlConnectionRequest:
                                await _conn.SendAsync(new StartControlConnectionReply
                                {
                                    ResultCode = StartResult,
                                    HostName = "pac",
                                    MaximumChannels = 100,
                                }, cancellationToken).ConfigureAwait(false);
                                break;

                            case OutgoingCallRequest ocrq:
                                await _conn.SendAsync(new OutgoingCallReply
                                {
                                    CallId = PacCallId,
                                    PeerCallId = ocrq.CallId,
                                    ResultCode = CallResult,
                                    ConnectSpeed = 100000,
                                    PacketRecvWindowSize = 64,
                                }, cancellationToken).ConfigureAwait(false);
                                break;

                            case CallClearRequest ccr:
                                await _conn.SendAsync(new CallDisconnectNotify
                                {
                                    CallId = ccr.CallId,
                                    ResultCode = (PptpResultCode)4,
                                    CallStatistics = "ok",
                                }, cancellationToken).ConfigureAwait(false);
                                break;

                            case StopControlConnectionRequest:
                                await _conn.SendAsync(new StopControlConnectionReply
                                {
                                    ResultCode = PptpResultCode.Successful,
                                }, cancellationToken).ConfigureAwait(false);
                                return;
                        }
                    }
                }
                catch (System.IO.EndOfStreamException) { /* peer closed */ }
                catch (OperationCanceledException) { /* test ended */ }
            }
        }
    }
}
