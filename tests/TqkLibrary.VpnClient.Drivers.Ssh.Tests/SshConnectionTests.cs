using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Drivers.Ssh.Config;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.Drivers.Ssh.Transport;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Ssh.Tests
{
    /// <summary>
    /// End-to-end offline tests for the SSH driver against the in-process <see cref="SimulatedSshServer"/>: the whole
    /// flow — version exchange, curve25519-sha256 KEX, ed25519 host-key verify, an AEAD cipher, publickey/password auth
    /// and the tun@openssh.com channel — runs over a loopback byte stream, and a bare IP packet sent on the L3 channel is
    /// echoed back by the server and observed inbound (proving the exchange-hash / KDF / cipher / tun framing are all
    /// self-consistent across the client and a second implementation). Also covers driver capabilities and auth rejection.
    /// </summary>
    public class SshConnectionTests
    {
        sealed class LoopbackTransportFactory : ISshTransportFactory
        {
            readonly IByteStreamTransport _clientEnd;
            public LoopbackTransportFactory(IByteStreamTransport clientEnd) => _clientEnd = clientEnd;
            public Task<IByteStreamTransport> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken) => Task.FromResult(_clientEnd);
        }

        static byte[] Seed(byte fill)
        {
            byte[] s = new byte[32];
            for (int i = 0; i < 32; i++) s[i] = (byte)(fill + i);
            return s;
        }

        static byte[] SampleIpv4Packet()
        {
            // A minimal well-formed-looking IPv4 packet body (version nibble 4). Content is opaque to the tunnel.
            byte[] p = new byte[40];
            p[0] = 0x45;
            for (int i = 1; i < p.Length; i++) p[i] = (byte)(i * 3 + 1);
            return p;
        }

        [Theory]
        [InlineData("chacha20-poly1305@openssh.com")]
        [InlineData("aes256-gcm@openssh.com")]
        public async Task FullHandshake_PublicKey_ThenIpRoundTrip(string cipherPreference)
        {
            var (clientEnd, serverEnd) = LoopbackByteStream.CreatePair();

            byte[] hostSeed = Seed(1);
            byte[] clientSeed = Seed(100);
            byte[] clientPublic = new Ed25519Signer().DerivePublicKey(clientSeed);

            // The server offers ONLY the cipher under test, so the client-preference negotiation lands on it.
            var server = new SimulatedSshServer(serverEnd, hostSeed, clientPublic, onlyCipher: cipherPreference);
            var serverTask = server.RunAsync(CancellationToken.None);

            var config = new SshConfig
            {
                Username = "tunuser",
                PrivateKeyEd25519 = clientSeed,
                TunnelAddress = IPAddress.Parse("10.10.0.2"),
                PeerAddress = IPAddress.Parse("10.10.0.1"),
            };

            var driver = new SshDriver(config, transportFactory: new LoopbackTransportFactory(clientEnd));
            await using IVpnConnection connection = await driver.ConnectAsync(new VpnEndpoint("127.0.0.1", 22), new VpnCredentials());

            IVpnSession session = Assert.Single(connection.Sessions);
            IPacketChannel channel = session.PacketChannel;

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            channel.InboundIpPacket += p => received.TrySetResult(p.ToArray());

            byte[] outbound = SampleIpv4Packet();
            await channel.WriteIpPacketAsync(outbound);

            byte[] echoed = await received.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(outbound, echoed);

            await connection.DisposeAsync();
            try { await serverTask.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
        }

        [Fact]
        public async Task FullHandshake_Password_Succeeds()
        {
            var (clientEnd, serverEnd) = LoopbackByteStream.CreatePair();
            byte[] hostSeed = Seed(7);
            var server = new SimulatedSshServer(serverEnd, hostSeed, authorizedClientPublic: null); // password mode
            var serverTask = server.RunAsync(CancellationToken.None);

            var config = new SshConfig
            {
                Username = "tunuser",
                Password = "pw",
                TunnelAddress = IPAddress.Parse("10.10.0.2"),
            };
            var driver = new SshDriver(config, transportFactory: new LoopbackTransportFactory(clientEnd));
            await using IVpnConnection connection = await driver.ConnectAsync(new VpnEndpoint("127.0.0.1", 22), new VpnCredentials());

            Assert.Single(connection.Sessions);
            await connection.DisposeAsync();
            try { await serverTask.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
        }

        [Fact]
        public async Task WrongPassword_FailsHandshake()
        {
            var (clientEnd, serverEnd) = LoopbackByteStream.CreatePair();
            var server = new SimulatedSshServer(serverEnd, Seed(9), authorizedClientPublic: null);
            var serverTask = server.RunAsync(CancellationToken.None);

            var config = new SshConfig { Username = "tunuser", Password = "wrong" };
            var driver = new SshDriver(config, transportFactory: new LoopbackTransportFactory(clientEnd));

            await Assert.ThrowsAnyAsync<Exception>(async () =>
                await driver.ConnectAsync(new VpnEndpoint("127.0.0.1", 22), new VpnCredentials()));
            try { await serverTask.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
        }

        [Fact]
        public void Capabilities_AreL3IpTcpOutOfBand()
        {
            var driver = new SshDriver(new SshConfig { Username = "u", Password = "p" });
            Assert.Equal(SshDriverConstants.DriverName, driver.Name);
            Assert.Equal(VpnLinkLayer.L3Ip, driver.Capabilities.LinkLayer);
            Assert.Equal(VpnTransportKind.Tcp, driver.Capabilities.TransportKinds);
            Assert.Equal(AddressAssignment.OutOfBand, driver.Capabilities.AddressAssignment);
            Assert.False(driver.Capabilities.UsesPpp);
        }

        [Fact]
        public void State_StartsDisconnected()
        {
            var conn = new SshConnection("h", 22, new SshConfig { Username = "u", Password = "p" },
                new LoopbackTransportFactory(LoopbackByteStream.CreatePair().a));
            Assert.Equal(VpnConnectionState.Disconnected, conn.State);
        }
    }
}
