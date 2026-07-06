using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Ayiya.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Ayiya.Tests
{
    /// <summary>
    /// Offline coverage for the AYIYA (Anything In Anything, static mode) driver runtime: the pure datagram codec
    /// (<see cref="AyiyaPacket"/> header round-trip / identity-length / big-endian epoch / shared-secret SHA-1 signature
    /// compute→verify and its reject paths) and the reused IPv6 passthrough data plane over a UDP datagram pipe framed by
    /// the <c>AyiyaFramingTransport</c> signer/verifier. No admin/server, no <c>Integration</c> trait — the real-socket
    /// case uses 127.0.0.1 ephemeral ports, the others an in-memory loopback link with a fixed epoch clock. AYIYA signs
    /// integrity + guards replay but does NOT encrypt.
    /// </summary>
    public class AyiyaTests
    {
        const string ServerHost = "203.0.113.7"; // TEST-NET-3 literal so the resolver returns it verbatim (no DNS)
        const string Password = "correct horse battery staple";
        const uint FixedEpoch = 1_000_000u;

        static readonly byte[] Identity = IPAddress.Parse("2001:db8::2").GetAddressBytes(); // 16-byte IPv6 identity → idlen 4
        static byte[] SecretHash => AyiyaPacket.HashPassword(AyiyaHashMethod.Sha1, Encoding.UTF8.GetBytes(Password));

        // ---- 1) codec: header round-trip ----

        [Theory]
        [InlineData(AyiyaIdType.Ipv6, AyiyaOpcode.Forward, (byte)41)]
        [InlineData(AyiyaIdType.String, AyiyaOpcode.EchoRequest, (byte)59)]
        [InlineData(AyiyaIdType.Integer, AyiyaOpcode.EchoResponse, (byte)4)]
        public void Header_Encode_ThenParse_RoundTripsAllFields(AyiyaIdType idType, AyiyaOpcode opcode, byte nextHeader)
        {
            byte[] payload = { 0xDE, 0xAD, 0xBE, 0xEF };
            byte[] datagram = AyiyaPacket.Encode(idType, Identity, AyiyaHashMethod.Sha1, AyiyaAuthMethod.SharedSecret,
                opcode, nextHeader, FixedEpoch, SecretHash, payload);

            Assert.True(AyiyaPacket.TryParse(datagram, out AyiyaHeader h));
            Assert.Equal(4, h.IdLen);                          // 16-byte identity → 2^4
            Assert.Equal(idType, h.IdType);
            Assert.Equal(5, h.SigLenWords);                    // SHA-1 = 20 bytes → siglen 5
            Assert.Equal(AyiyaHashMethod.Sha1, h.HashMethod);
            Assert.Equal(AyiyaAuthMethod.SharedSecret, h.AuthMethod);
            Assert.Equal(opcode, h.Opcode);
            Assert.Equal(nextHeader, h.NextHeader);
            Assert.Equal(FixedEpoch, h.EpochTime);
            Assert.Equal(16, h.IdentityLength);
            Assert.Equal(20, h.SignatureLength);
            Assert.Equal(AyiyaPacket.HeaderPrefixLength + 16 + 20, h.PayloadOffset);
            Assert.Equal(payload.Length, h.PayloadLength);
            Assert.Equal(payload, datagram.AsSpan(h.PayloadOffset).ToArray());
            Assert.Equal(Identity, datagram.AsSpan(h.IdentityOffset, h.IdentityLength).ToArray());
        }

        // ---- 2) codec: identity length is 2^idlen ----

        [Theory]
        [InlineData(1, 0)]
        [InlineData(2, 1)]
        [InlineData(4, 2)]
        [InlineData(8, 3)]
        [InlineData(16, 4)]
        public void Header_IdentityLength_Is2PowIdLen(int identityLength, int expectedIdLen)
        {
            byte[] identity = new byte[identityLength];
            byte[] datagram = AyiyaPacket.Encode(AyiyaIdType.String, identity, AyiyaHashMethod.Sha1,
                AyiyaAuthMethod.SharedSecret, AyiyaOpcode.Forward, IpProtocol.Ipv6, FixedEpoch, SecretHash, ReadOnlySpan<byte>.Empty);

            Assert.True(AyiyaPacket.TryParse(datagram, out AyiyaHeader h));
            Assert.Equal(expectedIdLen, h.IdLen);
            Assert.Equal(identityLength, h.IdentityLength);
            Assert.Equal(1 << h.IdLen, h.IdentityLength);
        }

        // ---- 3) codec: epoch time is big-endian at bytes 4..8 ----

        [Fact]
        public void Header_EpochTime_IsBigEndian()
        {
            const uint epoch = 0x01020304u;
            byte[] datagram = AyiyaPacket.Encode(AyiyaIdType.Ipv6, Identity, AyiyaHashMethod.Sha1,
                AyiyaAuthMethod.SharedSecret, AyiyaOpcode.Forward, IpProtocol.Ipv6, epoch, SecretHash, ReadOnlySpan<byte>.Empty);

            Assert.Equal(0x01, datagram[4]);
            Assert.Equal(0x02, datagram[5]);
            Assert.Equal(0x03, datagram[6]);
            Assert.Equal(0x04, datagram[7]);
            Assert.True(AyiyaPacket.TryParse(datagram, out AyiyaHeader h));
            Assert.Equal(epoch, h.EpochTime);
        }

        // ---- 4) codec: shared-secret signature compute → verify ----

        [Fact]
        public void Signature_ComputeThenVerify_Matches()
        {
            byte[] payload = IPAddress.Parse("2001:db8::1").GetAddressBytes();
            byte[] datagram = AyiyaPacket.Encode(AyiyaIdType.Ipv6, Identity, AyiyaHashMethod.Sha1,
                AyiyaAuthMethod.SharedSecret, AyiyaOpcode.Forward, IpProtocol.Ipv6, FixedEpoch, SecretHash, payload);

            Assert.True(AyiyaPacket.TryParse(datagram, out AyiyaHeader h));
            Assert.True(AyiyaPacket.VerifySignature(datagram, h, SecretHash));
            // The signature field is not just H(password) — it is the hash over the whole datagram.
            Assert.NotEqual(SecretHash, datagram.AsSpan(h.SignatureOffset, h.SignatureLength).ToArray());
        }

        [Fact]
        public void Verify_RejectsTamperedSignature()
        {
            byte[] datagram = AyiyaPacket.Encode(AyiyaIdType.Ipv6, Identity, AyiyaHashMethod.Sha1,
                AyiyaAuthMethod.SharedSecret, AyiyaOpcode.Forward, IpProtocol.Ipv6, FixedEpoch, SecretHash, new byte[] { 1, 2, 3 });

            Assert.True(AyiyaPacket.TryParse(datagram, out AyiyaHeader h));
            datagram[h.SignatureOffset] ^= 0xFF; // flip a signature byte
            Assert.False(AyiyaPacket.VerifySignature(datagram, h, SecretHash));
        }

        [Fact]
        public void Verify_RejectsWrongPassword()
        {
            byte[] datagram = AyiyaPacket.Encode(AyiyaIdType.Ipv6, Identity, AyiyaHashMethod.Sha1,
                AyiyaAuthMethod.SharedSecret, AyiyaOpcode.Forward, IpProtocol.Ipv6, FixedEpoch, SecretHash, new byte[] { 4, 5, 6 });

            Assert.True(AyiyaPacket.TryParse(datagram, out AyiyaHeader h));
            byte[] wrongSecret = AyiyaPacket.HashPassword(AyiyaHashMethod.Sha1, Encoding.UTF8.GetBytes("wrong-password"));
            Assert.False(AyiyaPacket.VerifySignature(datagram, h, wrongSecret));
        }

        // ---- 5) codec: runt / malformed rejection ----

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        [InlineData(6)]
        [InlineData(7)]
        public void TryParse_RejectsRunt(int length)
        {
            Assert.False(AyiyaPacket.TryParse(new byte[length], out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(3)]
        [InlineData(5)]
        [InlineData(6)]
        [InlineData(7)]
        [InlineData(17)]
        public void IdLenFor_RejectsNonPowerOfTwo(int identityLength)
        {
            Assert.Throws<ArgumentException>(() => AyiyaPacket.IdLenFor(identityLength));
        }

        // ---- 6) codec: heartbeat is echo-request / no-next-header / empty ----

        [Fact]
        public void Heartbeat_Encode_IsEchoRequest_NoNextHeader_Empty()
        {
            byte[] datagram = AyiyaPacket.Encode(AyiyaIdType.Ipv6, Identity, AyiyaHashMethod.Sha1,
                AyiyaAuthMethod.SharedSecret, AyiyaOpcode.EchoRequest, IpProtocol.NoNextHeader, FixedEpoch, SecretHash, ReadOnlySpan<byte>.Empty);

            Assert.True(AyiyaPacket.TryParse(datagram, out AyiyaHeader h));
            Assert.Equal(AyiyaOpcode.EchoRequest, h.Opcode);
            Assert.Equal(IpProtocol.NoNextHeader, h.NextHeader);
            Assert.Equal(0, h.PayloadLength);
            Assert.True(AyiyaPacket.VerifySignature(datagram, h, SecretHash));
        }

        // ---- 7) data plane: IPv6 passthrough round-trip both directions over the in-memory link ----

        [Fact]
        public async Task Tunnel_RoundTrips_Ipv6Packet_BothDirections()
        {
            var link = new LoopbackDatagramLink();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            IPacketChannel chA = await ConnectChannelAsync(link.A, cts.Token);
            IPacketChannel chB = await ConnectChannelAsync(link.B, cts.Token);

            var toB = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            var toA = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            chB.InboundIpPacket += p => toB.TrySetResult(p.ToArray());
            chA.InboundIpPacket += p => toA.TrySetResult(p.ToArray());

            byte[] a2b = BuildIpv6Packet(0xA1);
            await chA.WriteIpPacketAsync(a2b, cts.Token);
            Assert.Equal(a2b, await WaitAsync(toB.Task, cts.Token));

            byte[] b2a = BuildIpv6Packet(0xB2);
            await chB.WriteIpPacketAsync(b2a, cts.Token);
            Assert.Equal(b2a, await WaitAsync(toA.Task, cts.Token));
        }

        // ---- 8) receiver drops stale epoch / wrong next-header / wrong password, then delivers a valid datagram ----

        [Fact]
        public async Task Receiver_DropsStaleEpoch_ThenDeliversFresh()
        {
            var (channel, cts) = await ConnectReceiverAsync();
            using (cts)
            {
                var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                channel.InboundIpPacket += p => received.TrySetResult(p.ToArray());

                // A stale epoch (well outside the 120s tolerance) → dropped even though the signature is valid.
                await SendForwardAsync(cts, epoch: FixedEpoch - 10_000, secretHash: SecretHash, inner: BuildIpv6Packet(0x01));
                // A fresh epoch → delivered, proving the receive loop kept running.
                byte[] valid = BuildIpv6Packet(0x02);
                await SendForwardAsync(cts, epoch: FixedEpoch, secretHash: SecretHash, inner: valid);

                Assert.Equal(valid, await WaitAsync(received.Task, cts.Token));
            }
        }

        [Fact]
        public async Task Receiver_DropsWrongNextHeader_ThenDeliversValid()
        {
            var (channel, cts) = await ConnectReceiverAsync();
            using (cts)
            {
                var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                channel.InboundIpPacket += p => received.TrySetResult(p.ToArray());

                // next-header 47 (GRE) is neither IPv6 (41) nor a heartbeat (59) → dropped.
                await SendAsync(cts, AyiyaOpcode.Forward, nextHeader: IpProtocol.Gre, epoch: FixedEpoch, secretHash: SecretHash, inner: BuildIpv6Packet(0x11));
                byte[] valid = BuildIpv6Packet(0x22);
                await SendForwardAsync(cts, epoch: FixedEpoch, secretHash: SecretHash, inner: valid);

                Assert.Equal(valid, await WaitAsync(received.Task, cts.Token));
            }
        }

        [Fact]
        public async Task Receiver_DropsWrongPassword_ThenDeliversValid()
        {
            var (channel, cts) = await ConnectReceiverAsync();
            using (cts)
            {
                var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                channel.InboundIpPacket += p => received.TrySetResult(p.ToArray());

                // Signed with a different shared secret → signature verify fails → dropped.
                byte[] wrongSecret = AyiyaPacket.HashPassword(AyiyaHashMethod.Sha1, Encoding.UTF8.GetBytes("attacker"));
                await SendForwardAsync(cts, epoch: FixedEpoch, secretHash: wrongSecret, inner: BuildIpv6Packet(0x33));
                byte[] valid = BuildIpv6Packet(0x44);
                await SendForwardAsync(cts, epoch: FixedEpoch, secretHash: SecretHash, inner: valid);

                Assert.Equal(valid, await WaitAsync(received.Task, cts.Token));
            }
        }

        // ---- 9) real UDP loopback: AYIYA client <-> a raw UDP echo peer on 127.0.0.1 ----

        [Fact]
        public async Task Udp_Loopback_RoundTrips_Ipv6OverRealSocket()
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

            using var peer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            peer.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            int peerPort = ((IPEndPoint)peer.LocalEndPoint!).Port;
            var peerLoop = Task.Run(() => RunEchoPeerAsync(peer, cts.Token));

            // A reflecting peer echoes the whole AYIYA datagram back; the client verifies its own (valid) signature +
            // fresh epoch and surfaces the inner IPv6 packet.
            var options = new AyiyaOptions { Identity = Identity, Password = Password, Port = peerPort };
            var driver = new AyiyaDriver(options, transportFactory: new AyiyaUdpTransportFactory(IPAddress.Loopback));
            await using IVpnConnection conn = await driver.ConnectAsync(new VpnEndpoint("127.0.0.1", 0), new VpnCredentials(), cts.Token);
            IPacketChannel channel = conn.Sessions[0].PacketChannel;

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            channel.InboundIpPacket += p => received.TrySetResult(p.ToArray());

            byte[] inner = BuildIpv6Packet(0x77);
            await channel.WriteIpPacketAsync(inner, cts.Token);

            Assert.Equal(inner, await WaitAsync(received.Task, cts.Token));

            cts.Cancel();
            try { await peerLoop; } catch { }
        }

        // ---- 10) driver capabilities, defaults, guards ----

        [Fact]
        public void Driver_ExposesAyiyaCapabilities()
        {
            var driver = new AyiyaDriver(new AyiyaOptions { Identity = Identity, Password = Password });

            Assert.Equal("ayiya", driver.Name);
            Assert.False(driver.Capabilities.UsesPpp);
            Assert.False(driver.Capabilities.RequiresElevation);
            Assert.False(driver.Capabilities.RequiresRawIpSocket);
            Assert.Equal(VpnLinkLayer.L3Ip, driver.Capabilities.LinkLayer);
            Assert.True((driver.Capabilities.TransportKinds & VpnTransportKind.Udp) != 0);
            Assert.Equal(VpnSecurityKind.None, driver.Capabilities.SecurityKinds);          // payload UNENCRYPTED
            Assert.Equal(VpnAuthMethod.PreSharedKey, driver.Capabilities.AuthMethods);      // shared-secret signature
            Assert.Equal(AddressAssignment.OutOfBand, driver.Capabilities.AddressAssignment);
        }

        [Fact]
        public void Options_Defaults_AreSha1Ipv6Port5072()
        {
            var options = new AyiyaOptions { Identity = Identity, Password = Password };
            Assert.Equal(5072, options.Port);
            Assert.Equal(AyiyaIdType.Ipv6, options.IdType);
            Assert.Equal(AyiyaHashMethod.Sha1, options.HashMethod);
            Assert.Equal(AyiyaAuthMethod.SharedSecret, options.AuthMethod);
            Assert.Equal(1280, options.Mtu);
            Assert.Equal(120, options.ClockSkewToleranceSeconds);
        }

        [Fact]
        public void Driver_NullOptions_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new AyiyaDriver(null!));
        }

        [Fact]
        public void Connection_NullTransportFactory_Throws()
        {
            var options = new AyiyaOptions { Identity = Identity, Password = Password };
            Assert.Throws<ArgumentNullException>(() => new AyiyaConnection(ServerHost, null!, options));
        }

        [Fact]
        public void Options_InvalidIdentityLength_Throws()
        {
            var options = new AyiyaOptions { Identity = new byte[3], Password = Password }; // 3 is not a power of two
            Assert.Throws<ArgumentException>(() => options.ValidateAndComputeSecretHash());
        }

        // ---- helpers ----

        static async Task<IPacketChannel> ConnectChannelAsync(IDatagramTransport end, CancellationToken cancellationToken)
        {
            var options = new AyiyaOptions { Identity = Identity, Password = Password };
            var driver = new AyiyaDriver(options, transportFactory: new FakeAyiyaTransportFactory(end), epochClock: () => FixedEpoch);
            IVpnConnection conn = await driver.ConnectAsync(new VpnEndpoint(ServerHost, 0), new VpnCredentials(), cancellationToken);
            return conn.Sessions[0].PacketChannel;
        }

        // A receiver connection wrapping link.B with a fixed epoch clock; datagrams are injected via link.A.
        static async Task<(IPacketChannel channel, ReceiverContext ctx)> ConnectReceiverAsync()
        {
            var link = new LoopbackDatagramLink();
            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var options = new AyiyaOptions { Identity = Identity, Password = Password };
            var driver = new AyiyaDriver(options, transportFactory: new FakeAyiyaTransportFactory(link.B), epochClock: () => FixedEpoch);
            IVpnConnection conn = await driver.ConnectAsync(new VpnEndpoint(ServerHost, 0), new VpnCredentials(), cts.Token);
            return (conn.Sessions[0].PacketChannel, new ReceiverContext(link.A, cts, conn));
        }

        static ValueTask SendForwardAsync(ReceiverContext ctx, uint epoch, byte[] secretHash, byte[] inner)
            => SendAsync(ctx, AyiyaOpcode.Forward, IpProtocol.Ipv6, epoch, secretHash, inner);

        static ValueTask SendAsync(ReceiverContext ctx, AyiyaOpcode opcode, byte nextHeader, uint epoch, byte[] secretHash, byte[] inner)
        {
            byte[] datagram = AyiyaPacket.Encode(AyiyaIdType.Ipv6, Identity, AyiyaHashMethod.Sha1,
                AyiyaAuthMethod.SharedSecret, opcode, nextHeader, epoch, secretHash, inner);
            return ctx.Injector.SendAsync(datagram, ctx.Token);
        }

        // A raw UDP peer that reflects every datagram back to the sender's source endpoint (AYIYA carries its own header).
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

        // A minimal IPv6 packet (first nibble 6) so the passthrough channel carries a version-correct L3 packet.
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

        /// <summary>Carries the datagram injector (link.A), the lifetime CTS and the connection for a receiver-side test.</summary>
        sealed class ReceiverContext : IDisposable
        {
            readonly CancellationTokenSource _cts;
            readonly IVpnConnection _conn;
            public ReceiverContext(IDatagramTransport injector, CancellationTokenSource cts, IVpnConnection conn)
            {
                Injector = injector;
                _cts = cts;
                _conn = conn;
            }
            public IDatagramTransport Injector { get; }
            public CancellationToken Token => _cts.Token;
            public void Dispose()
            {
                try { _conn.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch { }
                _cts.Dispose();
            }
        }

        /// <summary>A fake <see cref="IAyiyaTransportFactory"/> handing out one preconfigured loopback datagram end as the UDP pipe.</summary>
        sealed class FakeAyiyaTransportFactory : IAyiyaTransportFactory
        {
            readonly IDatagramTransport _transport;
            public FakeAyiyaTransportFactory(IDatagramTransport transport) => _transport = transport;
            public IDatagramTransport Create(IPEndPoint remote) => _transport;
        }
    }
}
