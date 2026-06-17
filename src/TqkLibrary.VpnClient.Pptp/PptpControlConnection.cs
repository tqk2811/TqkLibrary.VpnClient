using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;
using TqkLibrary.VpnClient.Pptp.Models;

namespace TqkLibrary.VpnClient.Pptp
{
    /// <summary>
    /// Drives the PPTP control connection over the TCP/1723 byte stream (an <see cref="IByteStreamTransport"/>),
    /// acting as the PNS/client (RFC 2637 §3.1). It performs the two handshakes a VPN client needs — establish the
    /// control connection (Start-Control-Connection-Request ⇄ -Reply) then place the call (Outgoing-Call-Request ⇄
    /// -Reply) — and afterwards answers Echo-Requests, sends Echo keep-alives, applies Set-Link-Info, and tears the
    /// call/connection down (Call-Clear-Request / Stop-Control-Connection-Request, Call-Disconnect-Notify).
    /// <para>
    /// This is the <b>offline control plane only</b>. The actual user-data path is GRE (IP protocol 47), which needs
    /// a raw-IP transport (roadmap F.9, elevated). Once the call is established, <see cref="LocalCallId"/> and
    /// <see cref="PeerCallId"/> are the GRE Call-IDs a future data plane would use; the PPP engine (LCP/MS-CHAPv2/
    /// IPCP + the <see cref="Ccp.CcpNegotiator"/>) runs over that GRE channel.
    /// </para>
    /// All wire encoding/decoding is delegated to <see cref="PptpControlCodec"/>.
    /// </summary>
    public sealed class PptpControlConnection
    {
        // RFC 2637 has no read-buffer guidance; control packets are ≤168 bytes, so an MTU-sized read is plenty.
        const int ReadBufferSize = 1500;

        readonly IByteStreamTransport _transport;
        readonly PptpControlCodec _codec = new();
        readonly string _hostName;
        readonly string _vendorName;

        ushort _localCallId;
        uint _echoIdentifier;

        /// <summary>
        /// Wraps an already-connected control-connection byte stream. <paramref name="hostName"/> /
        /// <paramref name="vendorName"/> populate the Start-Control-Connection-Request identity fields.
        /// </summary>
        public PptpControlConnection(IByteStreamTransport transport, string hostName = "", string vendorName = "TqkLibrary.VpnClient")
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _hostName = hostName ?? string.Empty;
            _vendorName = vendorName ?? string.Empty;
        }

        /// <summary>Current state of the control connection / call.</summary>
        public PptpControlState State { get; private set; } = PptpControlState.Idle;

        /// <summary>The Call-ID we assigned for this call (GRE Call-ID for packets the peer sends us).</summary>
        public ushort LocalCallId => _localCallId;

        /// <summary>The Call-ID the peer assigned (GRE Call-ID we put on packets we send), valid after the call is up.</summary>
        public ushort PeerCallId { get; private set; }

        /// <summary>The Start-Control-Connection-Reply received from the peer (null until established).</summary>
        public StartControlConnectionReply? ServerStartReply { get; private set; }

        /// <summary>The Outgoing-Call-Reply received from the peer (null until the call is up).</summary>
        public OutgoingCallReply? ServerCallReply { get; private set; }

        /// <summary>Raised for every control message received (after the built-in handling).</summary>
        public event Action<IPptpControlMessage>? MessageReceived;

        /// <summary>
        /// Establishes the control connection: sends Start-Control-Connection-Request and waits for the matching
        /// reply. Throws <see cref="InvalidOperationException"/> if the peer refuses (Result-Code ≠ Successful).
        /// </summary>
        public async Task EstablishControlConnectionAsync(CancellationToken cancellationToken = default)
        {
            if (State != PptpControlState.Idle && State != PptpControlState.Closed)
                throw new InvalidOperationException($"Cannot start a control connection from state {State}.");

            var request = new StartControlConnectionRequest
            {
                HostName = _hostName,
                VendorName = _vendorName,
            };
            await SendAsync(request, cancellationToken).ConfigureAwait(false);
            State = PptpControlState.ControlConnectionRequested;

            var reply = (StartControlConnectionReply)await ReadOfTypeAsync(
                PptpControlMessageType.StartControlConnectionReply, cancellationToken).ConfigureAwait(false);

            if (reply.ResultCode != PptpResultCode.Successful)
            {
                State = PptpControlState.Closed;
                throw new InvalidOperationException(
                    $"PPTP server refused the control connection (Result-Code={reply.ResultCode}, Error-Code={reply.ErrorCode}).");
            }

            ServerStartReply = reply;
            State = PptpControlState.ControlConnectionEstablished;
        }

        /// <summary>
        /// Places the outgoing call: sends Outgoing-Call-Request with <paramref name="callId"/> (our GRE Call-ID) and
        /// waits for Outgoing-Call-Reply. On success records <see cref="PeerCallId"/>. Throws if the peer refuses.
        /// </summary>
        public async Task PlaceOutgoingCallAsync(ushort callId, CancellationToken cancellationToken = default)
        {
            if (State != PptpControlState.ControlConnectionEstablished)
                throw new InvalidOperationException($"Cannot place a call from state {State}.");

            _localCallId = callId;
            var request = new OutgoingCallRequest
            {
                CallId = callId,
                CallSerialNumber = callId,
                MinBps = 2400,
                MaxBps = 10000000,
            };
            await SendAsync(request, cancellationToken).ConfigureAwait(false);
            State = PptpControlState.OutgoingCallRequested;

            var reply = (OutgoingCallReply)await ReadOfTypeAsync(
                PptpControlMessageType.OutgoingCallReply, cancellationToken).ConfigureAwait(false);

            if (reply.ResultCode != PptpResultCode.Successful)
            {
                State = PptpControlState.ControlConnectionEstablished;
                throw new InvalidOperationException(
                    $"PPTP server refused the call (Result-Code={reply.ResultCode}, Error-Code={reply.ErrorCode}).");
            }

            ServerCallReply = reply;
            PeerCallId = reply.CallId; // the Call-ID we must put on GRE packets we send
            State = PptpControlState.CallEstablished;
        }

        /// <summary>Sends an Echo-Request keep-alive and returns the identifier the peer must echo back.</summary>
        public async Task<uint> SendEchoRequestAsync(CancellationToken cancellationToken = default)
        {
            uint id = unchecked(++_echoIdentifier);
            await SendAsync(new EchoRequest { Identifier = id }, cancellationToken).ConfigureAwait(false);
            return id;
        }

        /// <summary>Sends Set-Link-Info (the PPP ACCM maps) for the established call.</summary>
        public Task SendSetLinkInfoAsync(uint sendAccm = 0xFFFFFFFF, uint receiveAccm = 0xFFFFFFFF,
            CancellationToken cancellationToken = default)
            => SendAsync(new SetLinkInfo { PeerCallId = PeerCallId, SendAccm = sendAccm, ReceiveAccm = receiveAccm }, cancellationToken).AsTask();

        /// <summary>
        /// Clears the call: sends Call-Clear-Request and waits for Call-Disconnect-Notify, then returns the notify
        /// (whose statistics the caller may log). Moves to <see cref="PptpControlState.ControlConnectionEstablished"/>.
        /// </summary>
        public async Task<CallDisconnectNotify> ClearCallAsync(CancellationToken cancellationToken = default)
        {
            State = PptpControlState.Closing;
            await SendAsync(new CallClearRequest { CallId = _localCallId }, cancellationToken).ConfigureAwait(false);

            var cdn = (CallDisconnectNotify)await ReadOfTypeAsync(
                PptpControlMessageType.CallDisconnectNotify, cancellationToken).ConfigureAwait(false);

            State = ServerStartReply != null ? PptpControlState.ControlConnectionEstablished : PptpControlState.Closed;
            return cdn;
        }

        /// <summary>
        /// Stops the control connection: sends Stop-Control-Connection-Request and waits for the reply, then moves to
        /// <see cref="PptpControlState.Closed"/>.
        /// </summary>
        public async Task StopControlConnectionAsync(byte reason = 1, CancellationToken cancellationToken = default)
        {
            State = PptpControlState.Closing;
            await SendAsync(new StopControlConnectionRequest { Reason = reason }, cancellationToken).ConfigureAwait(false);

            await ReadOfTypeAsync(PptpControlMessageType.StopControlConnectionReply, cancellationToken).ConfigureAwait(false);
            State = PptpControlState.Closed;
        }

        /// <summary>Serialises and writes one control message to the transport.</summary>
        public ValueTask SendAsync(IPptpControlMessage message, CancellationToken cancellationToken = default)
            => _transport.WriteAsync(PptpControlCodec.Encode(message), cancellationToken);

        /// <summary>
        /// Reads the next complete control message off the stream (reassembling across reads). Built-in handling:
        /// Echo-Request → auto-reply; everything raises <see cref="MessageReceived"/>. Throws
        /// <see cref="System.IO.EndOfStreamException"/> if the stream closes before a full message arrives.
        /// </summary>
        public async Task<IPptpControlMessage> ReadMessageAsync(CancellationToken cancellationToken = default)
        {
            var readBuffer = new byte[ReadBufferSize];
            while (true)
            {
                if (_codec.TryReadMessage(out IPptpControlMessage message))
                {
                    if (message is EchoRequest echo)
                        await SendAsync(new EchoReply { Identifier = echo.Identifier }, cancellationToken).ConfigureAwait(false);
                    MessageReceived?.Invoke(message);
                    return message;
                }

                int read = await _transport.ReadAsync(readBuffer, cancellationToken).ConfigureAwait(false);
                if (read <= 0)
                    throw new System.IO.EndOfStreamException("PPTP control connection closed by the peer.");
                _codec.Append(readBuffer.AsSpan(0, read));
            }
        }

        // Reads messages until one of the expected type arrives (auto-handling Echo-Request keep-alives in between).
        async Task<IPptpControlMessage> ReadOfTypeAsync(PptpControlMessageType expected, CancellationToken cancellationToken)
        {
            while (true)
            {
                IPptpControlMessage message = await ReadMessageAsync(cancellationToken).ConfigureAwait(false);
                if (message.ControlMessageType == expected) return message;
                if (message is EchoRequest) continue; // already auto-replied
                // Tolerate other unsolicited messages (e.g. Set-Link-Info) while waiting for the expected reply.
            }
        }
    }
}
