using System.Text;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Tinc;
using TqkLibrary.VpnClient.Drivers.Tinc.DataChannel;
using TqkLibrary.VpnClient.Tinc.Hosts;
using TqkLibrary.VpnClient.Tinc.Meta;
using TqkLibrary.VpnClient.Tinc.Meta.Enums;
using TqkLibrary.VpnClient.Tinc.Sptps;
using TqkLibrary.VpnClient.Tinc.Sptps.Enums;

namespace TqkLibrary.VpnClient.Drivers.Tinc.Tests
{
    /// <summary>
    /// A throwaway in-process tinc 1.1 responder built from the same protocol blocks as the client. It runs the meta
    /// SPTPS handshake as the responder, sends an ACK line, answers the client's data-plane REQ_KEY by running the
    /// data-plane SPTPS responder (KEX + SIG over ANS_KEY), then opens inbound UDP data datagrams and echoes each inner
    /// IP packet straight back. The loopback is lossless and ordered, so there is no retransmit/reorder logic. This is
    /// the responder half of tinc's <c>protocol_auth.c</c> / <c>protocol_key.c</c> — it exists only for the offline test.
    /// </summary>
    sealed class SimulatedTincResponder
    {
        readonly IByteStreamTransport _meta;
        readonly DatagramPipe.End _udp;
        readonly string _myName;
        readonly byte[] _mySeed;
        readonly byte[] _myPublic;
        readonly string _clientName;
        readonly byte[] _clientPublic;

        readonly SptpsRecordLayer _record = new();
        readonly List<byte> _inbound = new();
        readonly byte[] _readBuffer = new byte[8192];

        readonly byte[] _myNodeId;
        readonly byte[] _clientNodeId;

        SptpsHandshake? _dataHandshake;
        SptpsDatagramRecordLayer? _dataRecord;
        byte[]? _myDataKex;
        TincDataTransport? _data;
        readonly object _sync = new();

        public int DataPacketsEchoed { get; private set; }

        public SimulatedTincResponder(IByteStreamTransport meta, DatagramPipe.End udp,
            string myName, byte[] mySeed, byte[] myPublic, string clientName, byte[] clientPublic)
        {
            _meta = meta;
            _udp = udp;
            _myName = myName;
            _mySeed = mySeed;
            _myPublic = myPublic;
            _clientName = clientName;
            _clientPublic = clientPublic;
            _myNodeId = TincNodeId.Compute(myName);
            _clientNodeId = TincNodeId.Compute(clientName);
            _udp.SetReceiver(OnInboundDatagram);
        }

        /// <summary>Runs the full responder meta protocol until the connection is torn down (or cancelled).</summary>
        public async Task RunAsync(CancellationToken cancellationToken)
        {
            // 1) Read the client ID, send ours.
            string clientId = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
            TincMetaRequest.Parse(clientId); // validate
            byte[] myId = TincMetaRequest.Id(_myName, TincDriverConstants.ProtocolMajor, TincDriverConstants.ProtocolMinor).ToBytes();
            await _meta.WriteAsync(myId, cancellationToken).ConfigureAwait(false);

            // 2) SPTPS meta handshake as the RESPONDER. Label = "tinc TCP key expansion <client> <me>" + NUL
            //    (responder puts the initiator/client name first, like protocol_auth.c's incoming branch).
            byte[] label = SptpsHandshake.BuildMetaLabel(_clientName, _myName);
            var hs = new SptpsHandshake(initiator: false, _mySeed, _clientPublic, label);

            // Responder sends its KEX immediately too (record seqno 0).
            byte[] myKex = hs.CreateKex();
            await _meta.WriteAsync(_record.EncodeHandshake(myKex), cancellationToken).ConfigureAwait(false);

            // Read client KEX, then client SIG. tinc's responder sends its SIG (record seqno 1) when it consumes the
            // client's SIG (inside receive_sig), and does NOT send/expect an empty ACK record — after consuming the
            // client SIG both sides are keyed (the in cipher is enabled internally via receive_ack(NULL,0)).
            (byte t1, byte[] clientKex) = await ReadRecordAsync(cancellationToken).ConfigureAwait(false);
            hs.ConsumeKex(clientKex);
            (byte t2, byte[] clientSig) = await ReadRecordAsync(cancellationToken).ConfigureAwait(false);
            if (!hs.ConsumeSig(clientSig)) throw new Exception("responder: client SIG verify failed");
            byte[] mySig = hs.CreateSig();
            await _meta.WriteAsync(_record.EncodeHandshake(mySig), cancellationToken).ConfigureAwait(false);

            // Now keyed (the meta ACK line is the first encrypted application record we send).
            _record.EnableEncryption(hs.OutCipherKey, hs.InCipherKey);

            // 3) Send our ACK line (request 4) + our ADD_SUBNET so the client routes us.
            await SendRequestAsync(new TincMetaRequest(TincRequestType.Ack, "655", "0", "7000000"), cancellationToken).ConfigureAwait(false);
            await SendRequestAsync(new TincMetaRequest(TincRequestType.AddSubnet, _myName, "10.99.0.1/32"), cancellationToken).ConfigureAwait(false);

            // 4) Process meta requests (the client's ACK, ADD_SUBNET, and the data-plane REQ_KEY).
            while (!cancellationToken.IsCancellationRequested)
            {
                TincMetaRequest? req = await ReadRequestAsync(cancellationToken).ConfigureAwait(false);
                if (req is null) return;
                await HandleRequestAsync(req, cancellationToken).ConfigureAwait(false);
            }
        }

        async Task HandleRequestAsync(TincMetaRequest req, CancellationToken cancellationToken)
        {
            switch (req.Type)
            {
                case TincRequestType.ReqKey:
                    // REQ_KEY "<from> <to> <reqno> <b64>" — the client's data KEX (and any SPTPS_PACKET data record).
                    if (req.Arguments.Count >= 4) await HandleDataRecordAsync(req.Arguments[2], req.Arguments[3], cancellationToken).ConfigureAwait(false);
                    break;
                case TincRequestType.AnsKey:
                    // ANS_KEY "<from> <to> <b64> -1 -1 -1 <comp>" — the client's data SIG (a SPTPS_HANDSHAKE record).
                    if (req.Arguments.Count >= 3) await HandleDataRecordAsync(null, req.Arguments[2], cancellationToken).ConfigureAwait(false);
                    break;
                case TincRequestType.Ping:
                    await SendRequestAsync(new TincMetaRequest(TincRequestType.Pong), cancellationToken).ConfigureAwait(false);
                    break;
                // Ack / AddSubnet / AddEdge from the client: nothing to do for the test.
            }
        }

        // The client's data-plane handshake KEX arrives via REQ_KEY (reqno 15) and its SIG via ANS_KEY (reqno null).
        // Start our responder data-plane SPTPS, answer with our KEX (after the KEX) then our SIG (after the SIG).
        async Task HandleDataRecordAsync(string? reqnoText, string b64, CancellationToken cancellationToken)
        {
            if (reqnoText is not null)
            {
                if (!int.TryParse(reqnoText, out int reqno)) return;
                if (reqno != (int)TincRequestType.ReqKey && reqno != (int)TincRequestType.SptpsPacket) return;
            }

            byte[] clientRecord = TincBase64.Decode(b64);

            SptpsHandshake? hs;
            SptpsDatagramRecordLayer? rec;
            lock (_sync) { hs = _dataHandshake; rec = _dataRecord; }
            if (hs is null)
            {
                // First REQ_KEY: start our data-plane responder. Label = "tinc UDP key expansion <client> <me>" + NUL.
                // Generate our ephemeral KEX immediately (SptpsHandshake requires CreateKex before ConsumeKex).
                byte[] label = SptpsHandshake.BuildUdpLabel(_clientName, _myName);
                hs = new SptpsHandshake(initiator: false, _mySeed, _clientPublic, label);
                byte[] myKex = hs.CreateKex(); // generate our ephemeral now; keep the bytes for the KEX record
                rec = new SptpsDatagramRecordLayer();
                lock (_sync) { _dataHandshake = hs; _dataRecord = rec; _myDataKex = myKex; }
            }

            // Decode the client's handshake record (seqno||128||payload).
            SptpsDecodeResult r = rec!.DecodeHandshake(clientRecord, out byte type, out byte[] data);
            if (r != SptpsDecodeResult.Ok || type != (byte)SptpsRecordType.Handshake) return;

            if (data.Length == SptpsConstants.NonceSize + SptpsConstants.EcdhSize + 1)
            {
                // Client KEX → consume it and send our KEX (seqno 0) over ANS_KEY. Our SIG follows once the client SIG
                // arrives (tinc's responder sends its SIG inside receive_sig, after consuming the client SIG).
                hs.ConsumeKex(data);
                byte[] myKexRecord = rec.EncodeHandshake((byte)SptpsRecordType.Handshake, _myDataKex!);
                await SendAnsKeyAsync(myKexRecord, cancellationToken).ConfigureAwait(false);
            }
            else if (data.Length == SptpsConstants.SignatureSize)
            {
                // Client SIG → verify, send our SIG (seqno 1), then we are keyed → bind our data transport.
                if (!hs.ConsumeSig(data)) throw new Exception("responder: client data SIG verify failed");
                byte[] mySigRecord = rec.EncodeHandshake((byte)SptpsRecordType.Handshake, hs.CreateSig());
                await SendAnsKeyAsync(mySigRecord, cancellationToken).ConfigureAwait(false);
                rec.EnableEncryption(hs.OutCipherKey, hs.InCipherKey);
                lock (_sync) _data = new TincDataTransport(rec, _myNodeId, _clientNodeId);
            }
        }

        async Task SendAnsKeyAsync(byte[] sptpsRecord, CancellationToken cancellationToken)
        {
            string b64 = TincBase64.Encode(sptpsRecord);
            // ANS_KEY "<from=me> <to=client> <b64> -1 -1 -1 <comp>"
            var req = new TincMetaRequest(TincRequestType.AnsKey, _myName, _clientName, b64, "-1", "-1", "-1", "0");
            await SendRequestAsync(req, cancellationToken).ConfigureAwait(false);
        }

        void OnInboundDatagram(ReadOnlyMemory<byte> datagram)
        {
            TincDataTransport? data;
            lock (_sync) data = _data;
            if (data is null) return;
            if (!data.TryOpen(datagram.Span, out byte[] inner)) return;
            DataPacketsEchoed++;
            _ = _udp.SendAsync(data.Seal(inner)); // echo the inner IP packet back
        }

        // ---- meta framing helpers ----

        Task SendRequestAsync(TincMetaRequest request, CancellationToken cancellationToken)
        {
            byte[] frame = _record.EncodeRecord(0, request.ToBytes());
            return _meta.WriteAsync(frame, cancellationToken).AsTask();
        }

        async Task<TincMetaRequest?> ReadRequestAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                (byte type, byte[] data) result;
                try { result = await ReadRecordAsync(cancellationToken).ConfigureAwait(false); }
                catch (EndOfStreamException) { return null; }
                if (result.type >= (byte)SptpsRecordType.Handshake) continue;
                string line = Encoding.ASCII.GetString(result.data).TrimEnd('\n');
                if (line.Length == 0) continue;
                return TincMetaRequest.Parse(line);
            }
        }

        async Task<(byte type, byte[] data)> ReadRecordAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                SptpsDecodeResult result = _record.TryDecodeRecord(_inbound.ToArray(), out byte type, out byte[] data, out int consumed);
                if (result == SptpsDecodeResult.Ok) { _inbound.RemoveRange(0, consumed); return (type, data); }
                if (result == SptpsDecodeResult.AuthFailed) throw new Exception("responder record auth failed");
                await FillAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        async Task<string> ReadLineAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                int nl = _inbound.IndexOf((byte)'\n');
                if (nl >= 0)
                {
                    var sb = new StringBuilder(nl);
                    for (int i = 0; i < nl; i++) { byte b = _inbound[i]; if (b != (byte)'\r') sb.Append((char)b); }
                    _inbound.RemoveRange(0, nl + 1);
                    return sb.ToString();
                }
                await FillAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        async Task FillAsync(CancellationToken cancellationToken)
        {
            int read = await _meta.ReadAsync(_readBuffer, cancellationToken).ConfigureAwait(false);
            if (read <= 0) throw new EndOfStreamException("responder meta closed");
            for (int i = 0; i < read; i++) _inbound.Add(_readBuffer[i]);
        }
    }
}
