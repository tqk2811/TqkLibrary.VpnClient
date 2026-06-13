using System.Net;
using TqkLibrary.Vpn.Drivers.Sstp;
using TqkLibrary.Vpn.Drivers.Sstp.Enums;
using TqkLibrary.Vpn.Drivers.Sstp.Models;
using TqkLibrary.Vpn.Ppp;
using TqkLibrary.Vpn.Ppp.Auth;
using Xunit;

namespace TqkLibrary.Vpn.Sstp.Tests
{
    /// <summary>
    /// Live MS-CHAPv2 authentication against a public VPN Gate SSTP server using the credentials vpn/vpn.
    /// Reaching CHAP Success proves the credentials and the full transport+PPP+auth stack.
    /// </summary>
    [Trait("Category", "Integration")]
    public class SstpAuthIntegrationTests
    {
        const string Host = "public-vpn-227.opengw.net";
        const string User = "vpn";
        const string Password = "vpn";

        readonly ITestOutputHelper _output;

        public SstpAuthIntegrationTests(ITestOutputHelper output) => _output = output;

        [Fact]
        public async Task MsChapV2_Authenticates_With_vpn_vpn()
        {
            using var transport = new SstpTransport(Host, 443);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));

            await transport.ConnectAsync(cts.Token);

            var encapsulatedProtocol = new SstpAttribute((byte)SstpAttributeId.EncapsulatedProtocolId, new byte[] { 0x00, 0x01 });
            await transport.SendControlAsync(SstpMessageType.CallConnectRequest, new[] { encapsulatedProtocol }, cts.Token);
            (bool _, byte[] ackBody) = await transport.ReadPacketAsync(cts.Token);
            Assert.Equal(SstpMessageType.CallConnectAck, SstpControlCodec.Parse(ackBody).MessageType);

            var channel = new SstpPppChannel(transport);
            int inboundFrames = 0;
            var protocols = new List<string>();
            channel.FrameReceived += frame =>
            {
                inboundFrames++;
                ReadOnlySpan<byte> s = frame.Span;
                int off = (s.Length >= 2 && s[0] == 0xFF && s[1] == 0x03) ? 2 : 0;
                if (s.Length >= off + 2) protocols.Add(((s[off] << 8) | s[off + 1]).ToString("X4"));
            };

            var authenticator = new MsChapV2Authenticator(User, Password);
            var engine = new PppEngine(channel, magic: 0x1A2B3C4D, localAddress: IPAddress.Any, authenticator: authenticator);

            var authResult = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            engine.AuthSucceeded += () => authResult.TrySetResult(true);
            engine.AuthFailed += () => authResult.TrySetResult(false);

            _ = Task.Run(() => channel.RunReadLoopAsync(cts.Token));
            engine.Start();

            Task finished = await Task.WhenAny(authResult.Task, Task.Delay(TimeSpan.FromSeconds(50)));
            string diag = $"data={channel.DataPacketsReceived}, control={channel.ControlPacketsReceived}, " +
                          $"pppFrames={inboundFrames}, protocols=[{string.Join(",", protocols)}], readError={channel.ReadError?.Message}";
            _output.WriteLine(diag);

            Assert.True(authResult.Task.IsCompleted, $"auth did not complete (timeout). {diag}");
            Assert.True(authResult.Task.Result, $"MS-CHAPv2 authentication failed (server rejected vpn/vpn). {diag}");
        }
    }
}
