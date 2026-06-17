using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Pptp;
using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;
using TqkLibrary.VpnClient.Pptp.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Pptp.Tests
{
    /// <summary>
    /// Drives the PPTP control-connection state machine (<see cref="PptpControlConnection"/>) against a simulated
    /// PAC over an in-memory loopback (offline). Covers the happy path (establish → call → echo → clear → stop),
    /// the Echo-Request auto-reply, and server refusals.
    /// </summary>
    public class PptpControlConnectionTests
    {
        [Fact]
        public async Task Establish_Place_Call_Clear_And_Stop_HappyPath()
        {
            var pipe = new LoopbackByteStreamPair();
            var client = new PptpControlConnection(pipe.Client, hostName: "client", vendorName: "test");
            var server = new SimulatedPac(pipe.Server);
            using var cts = new CancellationTokenSource(System.TimeSpan.FromSeconds(10));

            Task serverLoop = server.RunAsync(cts.Token);

            Assert.Equal(PptpControlState.Idle, client.State);

            await client.EstablishControlConnectionAsync(cts.Token);
            Assert.Equal(PptpControlState.ControlConnectionEstablished, client.State);
            Assert.NotNull(client.ServerStartReply);
            Assert.Equal(PptpResultCode.Successful, client.ServerStartReply!.ResultCode);

            await client.PlaceOutgoingCallAsync(callId: 0x4142, cancellationToken: cts.Token);
            Assert.Equal(PptpControlState.CallEstablished, client.State);
            Assert.Equal((ushort)0x4142, client.LocalCallId);
            Assert.Equal(SimulatedPac.PacCallId, client.PeerCallId); // GRE Call-ID the PAC assigned

            // Echo keep-alive: send a request, the PAC echoes it back.
            uint echoId = await client.SendEchoRequestAsync(cts.Token);
            var echoReply = (EchoReply)await client.ReadMessageAsync(cts.Token);
            Assert.Equal(echoId, echoReply.Identifier);

            // Clear the call → Call-Disconnect-Notify.
            CallDisconnectNotify cdn = await client.ClearCallAsync(cts.Token);
            Assert.Equal((ushort)0x4142, cdn.CallId);
            Assert.Equal(PptpControlState.ControlConnectionEstablished, client.State);

            // Stop the control connection.
            await client.StopControlConnectionAsync(reason: 1, cancellationToken: cts.Token);
            Assert.Equal(PptpControlState.Closed, client.State);

            server.Stop();
            await pipe.Client.DisposeAsync();
            await pipe.Server.DisposeAsync();
        }

        [Fact]
        public async Task Server_Refusing_Control_Connection_Throws()
        {
            var pipe = new LoopbackByteStreamPair();
            var client = new PptpControlConnection(pipe.Client);
            var server = new SimulatedPac(pipe.Server) { StartResult = PptpResultCode.NotAuthorized };
            using var cts = new CancellationTokenSource(System.TimeSpan.FromSeconds(10));
            _ = server.RunAsync(cts.Token);

            await Assert.ThrowsAsync<System.InvalidOperationException>(
                () => client.EstablishControlConnectionAsync(cts.Token));
            Assert.Equal(PptpControlState.Closed, client.State);
        }

        [Fact]
        public async Task Server_Refusing_Call_Throws_And_Keeps_ControlConnection()
        {
            var pipe = new LoopbackByteStreamPair();
            var client = new PptpControlConnection(pipe.Client);
            var server = new SimulatedPac(pipe.Server) { CallResult = PptpResultCode.GeneralError };
            using var cts = new CancellationTokenSource(System.TimeSpan.FromSeconds(10));
            _ = server.RunAsync(cts.Token);

            await client.EstablishControlConnectionAsync(cts.Token);
            await Assert.ThrowsAsync<System.InvalidOperationException>(
                () => client.PlaceOutgoingCallAsync(1, cts.Token));
            Assert.Equal(PptpControlState.ControlConnectionEstablished, client.State);
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

                            // Echo-Request is auto-answered inside ReadMessageAsync; nothing to do here.
                            case EchoRequest:
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
                catch (System.OperationCanceledException) { /* test ended */ }
            }
        }
    }
}
