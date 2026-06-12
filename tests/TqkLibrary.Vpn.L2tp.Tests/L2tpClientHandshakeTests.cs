using TqkLibrary.Vpn.L2tp;
using TqkLibrary.Vpn.L2tp.Enums;
using TqkLibrary.Vpn.L2tp.Models;
using Xunit;

namespace TqkLibrary.Vpn.L2tp.Tests
{
    /// <summary>
    /// Drives the real <see cref="L2tpClient"/> against an in-process LNS so the tunnel/session state machine and
    /// the Ns/Nr reliability are validated without a network: SCCRQ→SCCRP→SCCCN→ICRQ→ICRP→ICCN, then a data echo.
    /// </summary>
    public class L2tpClientHandshakeTests
    {
        [Fact]
        public async Task Connect_ThenDataEcho_Succeeds()
        {
            var link = new LoopbackLink();
            var lns = new SimulatedLns(link.Server);
            var client = new L2tpClient(link.Client, retransmitOptions: new L2tpRetransmitOptions { Interval = TimeSpan.FromSeconds(30) });

            string? echoed = null;
            var echoReceived = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.DataReceived += frame =>
            {
                echoed = System.Text.Encoding.ASCII.GetString(frame.ToArray());
                echoReceived.TrySetResult(true);
            };

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await client.ConnectAsync(cts.Token);

            Assert.NotEqual(0, client.PeerTunnelId);
            Assert.NotEqual(0, client.PeerSessionId);

            await client.SendDataAsync(System.Text.Encoding.ASCII.GetBytes("hello l2tp"));
            await Task.WhenAny(echoReceived.Task, Task.Delay(TimeSpan.FromSeconds(5), cts.Token));

            Assert.True(echoReceived.Task.IsCompletedSuccessfully);
            Assert.Equal("hello l2tp", echoed);

            client.Dispose();
        }

        /// <summary>An in-memory bidirectional L2TP link; each side posts datagrams to the other via the thread pool.</summary>
        sealed class LoopbackLink
        {
            readonly Endpoint _client = new();
            readonly Endpoint _server = new();

            public LoopbackLink()
            {
                _client.Peer = _server;
                _server.Peer = _client;
            }

            public IL2tpTransport Client => _client;
            public IL2tpTransport Server => _server;

            sealed class Endpoint : IL2tpTransport
            {
                public Endpoint? Peer;
                public event Action<ReadOnlyMemory<byte>>? DatagramReceived;

                public Task SendAsync(ReadOnlyMemory<byte> datagram)
                {
                    byte[] copy = datagram.ToArray();
                    Endpoint? peer = Peer;
                    _ = Task.Run(() => peer?.DatagramReceived?.Invoke(copy));
                    return Task.CompletedTask;
                }
            }
        }

        /// <summary>A throwaway LNS: answers SCCRQ/ICRQ with the matching replies and echoes any data frame.</summary>
        sealed class SimulatedLns
        {
            readonly IL2tpTransport _transport;
            ushort _ns;
            ushort _nr;
            ushort _clientTunnelId;
            ushort _clientSessionId;
            readonly ushort _tunnelId = 0x5000;
            readonly ushort _sessionId = 0x6000;

            public SimulatedLns(IL2tpTransport transport)
            {
                _transport = transport;
                _transport.DatagramReceived += OnDatagram;
            }

            void OnDatagram(ReadOnlyMemory<byte> datagram)
            {
                if (!L2tpCodec.IsControl(datagram.Span))
                {
                    if (L2tpCodec.TryDecodeData(datagram.Span, out _, out _, out byte[] ppp))
                        _ = _transport.SendAsync(L2tpCodec.EncodeData(_clientTunnelId, _clientSessionId, ppp));
                    return;
                }

                L2tpControlMessage message = L2tpCodec.DecodeControl(datagram.Span);
                if (message.IsZeroLengthBody) return;
                _nr = (ushort)(message.Ns + 1);

                switch (message.MessageType)
                {
                    case L2tpMessageType.StartControlConnectionRequest:
                        _clientTunnelId = message.Find(L2tpAvpType.AssignedTunnelId)!.AsUInt16();
                        Reply(L2tpControlMessage.Create(L2tpMessageType.StartControlConnectionReply, _clientTunnelId)
                            .With(L2tpAvp.UInt16(L2tpAvpType.ProtocolVersion, 0x0100))
                            .With(L2tpAvp.UInt32(L2tpAvpType.FramingCapabilities, 3))
                            .With(L2tpAvp.Text(L2tpAvpType.HostName, "lns"))
                            .With(L2tpAvp.UInt16(L2tpAvpType.AssignedTunnelId, _tunnelId)));
                        break;

                    case L2tpMessageType.IncomingCallRequest:
                        _clientSessionId = message.Find(L2tpAvpType.AssignedSessionId)!.AsUInt16();
                        Reply(L2tpControlMessage.Create(L2tpMessageType.IncomingCallReply, _clientTunnelId)
                            .With(L2tpAvp.UInt16(L2tpAvpType.AssignedSessionId, _sessionId)));
                        break;
                }
            }

            void Reply(L2tpControlMessage message)
            {
                message.Ns = _ns++;
                message.Nr = _nr;
                _ = _transport.SendAsync(L2tpCodec.EncodeControl(message));
            }
        }
    }
}
