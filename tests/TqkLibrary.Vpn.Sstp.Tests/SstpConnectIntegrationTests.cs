using System.Net;
using System.Security.Cryptography;
using TqkLibrary.Vpn.Drivers.Sstp;
using TqkLibrary.Vpn.Drivers.Sstp.Enums;
using TqkLibrary.Vpn.Drivers.Sstp.Models;
using TqkLibrary.Vpn.Ppp;
using TqkLibrary.Vpn.Ppp.Auth;
using Xunit;
using Xunit.Abstractions;

namespace TqkLibrary.Vpn.Sstp.Tests
{
    /// <summary>
    /// Full live SSTP connect against a public VPN Gate server: TLS + control + PPP + MS-CHAPv2 + crypto binding
    /// + IPCP, ending with a server-assigned IP address.
    /// </summary>
    [Trait("Category", "Integration")]
    public class SstpConnectIntegrationTests
    {
        const string Host = "public-vpn-227.opengw.net";
        const string User = "vpn";
        const string Password = "vpn";

        readonly ITestOutputHelper _output;

        public SstpConnectIntegrationTests(ITestOutputHelper output) => _output = output;

        [Fact]
        public async Task Connects_AndObtainsIpAddress()
        {
            using var transport = new SstpTransport(Host, 443);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(70));

            await transport.ConnectAsync(cts.Token);

            var encapsulatedProtocol = new SstpAttribute((byte)SstpAttributeId.EncapsulatedProtocolId, new byte[] { 0x00, 0x01 });
            await transport.SendControlAsync(SstpMessageType.CallConnectRequest, new[] { encapsulatedProtocol }, cts.Token);
            (bool _, byte[] ackBody) = await transport.ReadPacketAsync(cts.Token);
            SstpControlMessage ack = SstpControlCodec.Parse(ackBody);
            Assert.Equal(SstpMessageType.CallConnectAck, ack.MessageType);

            SstpAttribute cryptoReq = ack.Find(SstpAttributeId.CryptoBindingReq)!;
            byte[] nonce = new byte[32];
            Buffer.BlockCopy(cryptoReq.Value, 4, nonce, 0, 32); // Reserved(3) + Bitmask(1) + Nonce(32)

            var channel = new SstpPppChannel(transport);
            SstpMessageType? lastControl = null;
            channel.ControlReceived += m => lastControl = m.MessageType;

            var authenticator = new MsChapV2Authenticator(User, Password);
            var engine = new PppEngine(channel, magic: 0x1A2B3C4D, localAddress: IPAddress.Any, authenticator: authenticator);

            engine.AuthSucceeded += () =>
            {
                byte[] hlak = authenticator.DeriveHlak();
                byte[] certHash = SHA256.HashData(transport.ServerCertificate!.RawData);
                SstpAttribute cryptoBinding = SstpCryptoBinding.BuildCryptoBinding(hlak, nonce, certHash);
                _ = transport.SendControlAsync(SstpMessageType.CallConnected, new[] { cryptoBinding }, cts.Token);
            };

            var linkUp = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            engine.LinkUp += () => linkUp.TrySetResult(true);

            _ = Task.Run(() => channel.RunReadLoopAsync(cts.Token));
            engine.Start();

            await Task.WhenAny(linkUp.Task, Task.Delay(TimeSpan.FromSeconds(60)));

            string diag = $"linkUp={linkUp.Task.IsCompleted}, assigned={engine.AssignedAddress}, dns={engine.AssignedDns}, " +
                          $"lastControl={lastControl}, data={channel.DataPacketsReceived}, control={channel.ControlPacketsReceived}, " +
                          $"readError={channel.ReadError?.Message}";
            _output.WriteLine(diag);

            Assert.True(linkUp.Task.IsCompleted, $"did not obtain an IP. {diag}");
            Assert.NotEqual(IPAddress.Any, engine.AssignedAddress);
        }
    }
}
