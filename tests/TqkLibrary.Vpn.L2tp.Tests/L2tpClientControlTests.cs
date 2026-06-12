using TqkLibrary.Vpn.L2tp;
using TqkLibrary.Vpn.L2tp.Enums;
using TqkLibrary.Vpn.L2tp.Models;
using Xunit;

namespace TqkLibrary.Vpn.L2tp.Tests
{
    /// <summary>
    /// Verifies the keepalive/teardown control messages the client emits after a tunnel is up: HELLO (keepalive),
    /// CDN (session teardown) and StopCCN (tunnel teardown), with the Result Code / Assigned Tunnel ID AVPs.
    /// </summary>
    public class L2tpClientControlTests
    {
        [Fact]
        public async Task Hello_Cdn_StopCcn_AreSentWithTheRightTypeAndAvps()
        {
            var link = new LoopbackLink();
            var lns = new RecordingLns(link.Server);
            var client = new L2tpClient(link.Client, retransmitOptions: new L2tpRetransmitOptions { Interval = TimeSpan.FromSeconds(30) });

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await client.ConnectAsync(cts.Token);

            await client.SendHelloAsync();
            await client.SendCallDisconnectAsync();
            await client.SendStopControlConnectionAsync();

            L2tpControlMessage hello = await WithTimeout(lns.WaitFor(L2tpMessageType.Hello));
            Assert.Equal(L2tpMessageType.Hello, hello.MessageType);

            L2tpControlMessage cdn = await WithTimeout(lns.WaitFor(L2tpMessageType.CallDisconnectNotify));
            Assert.NotNull(cdn.Find(L2tpAvpType.ResultCode));

            L2tpControlMessage stop = await WithTimeout(lns.WaitFor(L2tpMessageType.StopControlConnectionNotification));
            Assert.NotNull(stop.Find(L2tpAvpType.ResultCode));
            Assert.Equal(client.LocalTunnelId, stop.Find(L2tpAvpType.AssignedTunnelId)!.AsUInt16());

            client.Dispose();
        }

        static async Task<L2tpControlMessage> WithTimeout(Task<L2tpControlMessage> task)
        {
            Task completed = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.True(completed == task, "timed out waiting for the control message");
            return await task;
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

        /// <summary>An LNS that completes the handshake and records every other control message by type.</summary>
        sealed class RecordingLns
        {
            const ushort TunnelId = 0x5000;
            const ushort SessionId = 0x6000;

            readonly IL2tpTransport _transport;
            readonly object _sync = new();
            readonly Dictionary<L2tpMessageType, TaskCompletionSource<L2tpControlMessage>> _waiters = new();
            ushort _ns;
            ushort _nr;
            ushort _clientTunnelId;

            public RecordingLns(IL2tpTransport transport)
            {
                _transport = transport;
                _transport.DatagramReceived += OnDatagram;
            }

            public Task<L2tpControlMessage> WaitFor(L2tpMessageType type)
            {
                lock (_sync) return Waiter(type).Task;
            }

            TaskCompletionSource<L2tpControlMessage> Waiter(L2tpMessageType type)
            {
                if (!_waiters.TryGetValue(type, out TaskCompletionSource<L2tpControlMessage>? tcs))
                {
                    tcs = new TaskCompletionSource<L2tpControlMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
                    _waiters[type] = tcs;
                }
                return tcs;
            }

            void OnDatagram(ReadOnlyMemory<byte> datagram)
            {
                if (!L2tpCodec.IsControl(datagram.Span)) return;
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
                            .With(L2tpAvp.UInt16(L2tpAvpType.AssignedTunnelId, TunnelId)));
                        break;

                    case L2tpMessageType.IncomingCallRequest:
                        Reply(L2tpControlMessage.Create(L2tpMessageType.IncomingCallReply, _clientTunnelId)
                            .With(L2tpAvp.UInt16(L2tpAvpType.AssignedSessionId, SessionId)));
                        break;

                    default:
                        lock (_sync) Waiter(message.MessageType).TrySetResult(message);
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
