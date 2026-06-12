using System.Security.Cryptography;
using TqkLibrary.Vpn.L2tp.Enums;
using TqkLibrary.Vpn.L2tp.Models;

namespace TqkLibrary.Vpn.L2tp
{
    /// <summary>
    /// An L2TPv2 client (LAC side): brings up one tunnel (SCCRQ→SCCRP→SCCCN) and one session
    /// (ICRQ→ICRP→ICCN), then carries PPP frames in L2TP data messages. The PPP layer runs on top via the
    /// <see cref="DataReceived"/> event and <see cref="SendDataAsync"/>.
    /// </summary>
    public sealed class L2tpClient : IDisposable
    {
        readonly IL2tpTransport _transport;
        readonly L2tpControlChannel _control;
        readonly string _hostName;
        readonly TaskCompletionSource<bool> _tunnelUp = new(TaskCreationOptions.RunContinuationsAsynchronously);
        readonly TaskCompletionSource<bool> _sessionUp = new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>
        /// Creates a client over <paramref name="transport"/>; <paramref name="hostName"/> is sent as the Host Name AVP.
        /// <paramref name="retransmitOptions"/> tunes the control channel's resend interval, backoff and cap (null = default).
        /// </summary>
        public L2tpClient(IL2tpTransport transport, string hostName = "anonymous", L2tpRetransmitOptions? retransmitOptions = null)
        {
            _transport = transport;
            _hostName = hostName;
            LocalTunnelId = RandomId();
            LocalSessionId = RandomId();
            _control = new L2tpControlChannel(transport.SendAsync, retransmitOptions);
            _control.ControlReceived += OnControl;
            _control.Failed += OnControlFailed;
            _transport.DatagramReceived += OnDatagram;
        }

        /// <summary>The tunnel id we assigned (the server addresses us with it).</summary>
        public ushort LocalTunnelId { get; }

        /// <summary>The session id we assigned (the server addresses us with it).</summary>
        public ushort LocalSessionId { get; }

        /// <summary>The tunnel id the server assigned (we address it with this).</summary>
        public ushort PeerTunnelId { get; private set; }

        /// <summary>The session id the server assigned (we address it with this).</summary>
        public ushort PeerSessionId { get; private set; }

        /// <summary>Raised for each inbound PPP frame carried by an L2TP data message for our session.</summary>
        public event Action<ReadOnlyMemory<byte>>? DataReceived;

        /// <summary>Raised when the server tears the tunnel/session down (StopCCN or CDN) after it was established.</summary>
        public event Action<string>? Disconnected;

        /// <summary>Brings up the tunnel and session, completing once the session is established.</summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            await SendSccrqAsync().ConfigureAwait(false);
            await WaitAsync(_tunnelUp.Task, cancellationToken).ConfigureAwait(false);

            await SendIcrqAsync().ConfigureAwait(false);
            await WaitAsync(_sessionUp.Task, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Sends a PPP frame inside an L2TP data message addressed to the server's tunnel/session.</summary>
        public Task SendDataAsync(ReadOnlyMemory<byte> pppFrame)
            => _transport.SendAsync(L2tpCodec.EncodeData(PeerTunnelId, PeerSessionId, pppFrame.Span));

        /// <summary>Sends an L2TP HELLO keepalive on the reliable control channel (RFC 2661 §5.5).</summary>
        public Task SendHelloAsync()
            => _control.SendAsync(L2tpControlMessage.Create(L2tpMessageType.Hello, PeerTunnelId));

        /// <summary>Sends a Call-Disconnect-Notify for the session (RFC 2661 §5.6); <paramref name="resultCode"/> 3 = administrative.</summary>
        public Task SendCallDisconnectAsync(ushort resultCode = 3)
        {
            var cdn = L2tpControlMessage.Create(L2tpMessageType.CallDisconnectNotify, PeerTunnelId)
                .With(L2tpAvp.UInt16(L2tpAvpType.ResultCode, resultCode));
            cdn.SessionId = PeerSessionId;
            return _control.SendAsync(cdn);
        }

        /// <summary>Sends a Stop-Control-Connection-Notification to tear the tunnel down; <paramref name="resultCode"/> 1 = general request to clear.</summary>
        public Task SendStopControlConnectionAsync(ushort resultCode = 1)
            => _control.SendAsync(L2tpControlMessage.Create(L2tpMessageType.StopControlConnectionNotification, PeerTunnelId)
                .With(L2tpAvp.UInt16(L2tpAvpType.ResultCode, resultCode))
                .With(L2tpAvp.UInt16(L2tpAvpType.AssignedTunnelId, LocalTunnelId)));

        Task SendSccrqAsync()
        {
            var sccrq = L2tpControlMessage.Create(L2tpMessageType.StartControlConnectionRequest, 0)
                .With(L2tpAvp.UInt16(L2tpAvpType.ProtocolVersion, 0x0100))
                .With(L2tpAvp.UInt32(L2tpAvpType.FramingCapabilities, 3))   // async + sync
                .With(L2tpAvp.UInt32(L2tpAvpType.BearerCapabilities, 3))
                .With(L2tpAvp.Text(L2tpAvpType.HostName, _hostName))
                .With(L2tpAvp.Text(L2tpAvpType.VendorName, "TqkLibrary", mandatory: false))
                .With(L2tpAvp.UInt16(L2tpAvpType.AssignedTunnelId, LocalTunnelId))
                .With(L2tpAvp.UInt16(L2tpAvpType.ReceiveWindowSize, 8));
            return _control.SendAsync(sccrq);
        }

        Task SendScccnAsync()
            => _control.SendAsync(L2tpControlMessage.Create(L2tpMessageType.StartControlConnectionConnected, PeerTunnelId));

        Task SendIcrqAsync()
        {
            var icrq = L2tpControlMessage.Create(L2tpMessageType.IncomingCallRequest, PeerTunnelId)
                .With(L2tpAvp.UInt16(L2tpAvpType.AssignedSessionId, LocalSessionId))
                .With(L2tpAvp.UInt32(L2tpAvpType.CallSerialNumber, 1));
            return _control.SendAsync(icrq);
        }

        Task SendIccnAsync()
        {
            var iccn = L2tpControlMessage.Create(L2tpMessageType.IncomingCallConnected, PeerTunnelId)
                .With(L2tpAvp.UInt32(L2tpAvpType.TxConnectSpeed, 100000))
                .With(L2tpAvp.UInt32(L2tpAvpType.FramingType, 1)); // synchronous
            iccn.SessionId = PeerSessionId;
            return _control.SendAsync(iccn);
        }

        void OnControl(L2tpControlMessage message)
        {
            switch (message.MessageType)
            {
                case L2tpMessageType.StartControlConnectionReply:
                    L2tpAvp? tunnelId = message.Find(L2tpAvpType.AssignedTunnelId);
                    if (tunnelId != null)
                    {
                        PeerTunnelId = tunnelId.AsUInt16();
                        _control.PeerTunnelId = PeerTunnelId;
                    }
                    _ = SendScccnAsync();
                    _tunnelUp.TrySetResult(true);
                    break;

                case L2tpMessageType.IncomingCallReply:
                    L2tpAvp? sessionId = message.Find(L2tpAvpType.AssignedSessionId);
                    if (sessionId != null) PeerSessionId = sessionId.AsUInt16();
                    _ = SendIccnAsync();
                    _sessionUp.TrySetResult(true);
                    break;

                case L2tpMessageType.StopControlConnectionNotification:
                    Fail("Server sent StopCCN (tunnel rejected).");
                    Disconnected?.Invoke("Server sent StopCCN (tunnel down).");
                    break;

                case L2tpMessageType.CallDisconnectNotify:
                    Fail("Server sent CDN (call disconnected).");
                    Disconnected?.Invoke("Server sent CDN (call disconnected).");
                    break;
            }
        }

        void OnDatagram(ReadOnlyMemory<byte> datagram)
        {
            if (L2tpCodec.IsControl(datagram.Span))
            {
                _control.OnDatagram(datagram);
            }
            else if (L2tpCodec.TryDecodeData(datagram.Span, out _, out ushort sessionId, out byte[] pppFrame)
                     && sessionId == LocalSessionId)
            {
                DataReceived?.Invoke(pppFrame);
            }
        }

        void Fail(string reason)
        {
            _tunnelUp.TrySetException(new IOException(reason));
            _sessionUp.TrySetException(new IOException(reason));
        }

        // The reliable control channel exhausted its retransmit budget: surface it both as a handshake failure
        // (unblocks an in-progress ConnectAsync) and as a Disconnected drop (triggers the driver's reconnect).
        void OnControlFailed(string reason)
        {
            Fail(reason);
            Disconnected?.Invoke(reason);
        }

        static async Task WaitAsync(Task task, CancellationToken cancellationToken)
        {
            var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (cancellationToken.Register(() => cancelled.TrySetResult(true)))
            {
                Task completed = await Task.WhenAny(task, cancelled.Task).ConfigureAwait(false);
                if (completed != task)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }
            }
            await task.ConfigureAwait(false);
        }

        static ushort RandomId()
        {
            byte[] bytes = new byte[2];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            ushort id = (ushort)((bytes[0] << 8) | bytes[1]);
            return id == 0 ? (ushort)1 : id;
        }

        /// <inheritdoc/>
        public void Dispose() => _control.Dispose();
    }
}
