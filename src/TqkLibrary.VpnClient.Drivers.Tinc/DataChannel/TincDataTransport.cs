using TqkLibrary.VpnClient.Tinc.Sptps;
using TqkLibrary.VpnClient.Tinc.Sptps.Enums;

namespace TqkLibrary.VpnClient.Drivers.Tinc.DataChannel
{
    /// <summary>
    /// The tinc data (transport) plane for one established data-plane SPTPS session. It wraps the phase-a
    /// <see cref="SptpsDatagramRecordLayer"/> (seqno + ChaCha-Poly1305 + anti-replay) and adds tinc's UDP <b>relay
    /// header</b> so a 1.1 peer can demux a datagram before it has confirmed our UDP address.
    /// <para>
    /// Wire layout (matching tinc's <c>send_sptps_data</c> / <c>handle_incoming_vpn_packet</c> when the peer is relay-
    /// capable — <c>options&gt;&gt;24 &gt;= 4</c>, true for 1.1pre18): <c>DSTID(6) ‖ SRCID(6) ‖ seqno(4 BE) ‖
    /// encrypt(seqno, type(1) ‖ IP) ‖ tag(16)</c>. For a <b>direct</b> point-to-point packet (no intermediate relay)
    /// <c>DSTID</c> is the all-zero null id, which tells the receiver "this came straight from the source" — it then
    /// reads <c>SRCID</c> to find the session. <c>SRCID</c> is the sender's node id (the first 6 bytes of
    /// <c>SHA512(name)</c>). The record type for a router-mode IP packet is 0 (no Ethernet, no compression).
    /// </para>
    /// </summary>
    public sealed class TincDataTransport
    {
        readonly SptpsDatagramRecordLayer _record;
        readonly byte[] _localNodeId;   // OUR node id — stamped as SRCID on datagrams we send
        readonly byte[] _peerNodeId;    // the PEER's node id — datagrams from it carry this as SRCID
        readonly object _sync = new();

        ulong _sentPacketCount;
        ulong _receivedPacketCount;

        /// <summary>
        /// Builds a data transport over an already-keyed <paramref name="record"/> layer (the data-plane SPTPS handshake
        /// ran over the meta-connection, so the layer's send/receive seqnos already continue past the handshake records).
        /// <paramref name="localNodeId"/> / <paramref name="peerNodeId"/> are the 6-byte node ids of this client and the
        /// peer (see <see cref="TincNodeId"/>).
        /// </summary>
        public TincDataTransport(SptpsDatagramRecordLayer record, byte[] localNodeId, byte[] peerNodeId)
        {
            if (localNodeId is null || localNodeId.Length != TincDriverConstants.NodeIdLength)
                throw new ArgumentException("localNodeId must be 6 bytes.", nameof(localNodeId));
            if (peerNodeId is null || peerNodeId.Length != TincDriverConstants.NodeIdLength)
                throw new ArgumentException("peerNodeId must be 6 bytes.", nameof(peerNodeId));
            _record = record ?? throw new ArgumentNullException(nameof(record));
            _localNodeId = (byte[])localNodeId.Clone();
            _peerNodeId = (byte[])peerNodeId.Clone();
        }

        /// <summary>The number of data packets sealed so far.</summary>
        public ulong SentPacketCount { get { lock (_sync) return _sentPacketCount; } }

        /// <summary>The number of data packets opened so far.</summary>
        public ulong ReceivedPacketCount { get { lock (_sync) return _receivedPacketCount; } }

        /// <summary>
        /// Seals an inner IP packet into a UDP data datagram: <c>nullid(6) ‖ SRCID(6) ‖ seqno(4) ‖ ciphertext ‖
        /// tag(16)</c>. <c>DSTID</c> is the null id (a direct, non-relayed packet); <c>SRCID</c> is our node id.
        /// </summary>
        public byte[] Seal(ReadOnlySpan<byte> ipPacket) => SealRecord(TincDriverConstants.RouterPacketType, ipPacket);

        /// <summary>
        /// Seals an arbitrary record (type + payload) into a UDP data datagram with the relay header. Used for both the
        /// router-mode IP packet (type 0) and a UDP probe reply (type <c>PKT_PROBE</c>).
        /// </summary>
        public byte[] SealRecord(byte type, ReadOnlySpan<byte> payload)
        {
            byte[] record;
            lock (_sync)
            {
                record = _record.Encode(type, payload);
                _sentPacketCount++;
            }

            int idLen = TincDriverConstants.NodeIdLength;
            byte[] wire = new byte[idLen + idLen + record.Length];
            // DSTID = null id (zero-filled by default) → direct packet.
            Array.Copy(_localNodeId, 0, wire, idLen, idLen); // SRCID = our node id
            Array.Copy(record, 0, wire, idLen + idLen, record.Length);
            return wire;
        }

        /// <summary>
        /// Opens an incoming UDP data datagram into an inner IP packet (only router-mode type-0 records). Convenience
        /// over <see cref="TryOpenRecord"/> that drops anything that is not a data packet.
        /// </summary>
        public bool TryOpen(ReadOnlySpan<byte> datagram, out byte[] plaintext)
        {
            plaintext = Array.Empty<byte>();
            if (!TryOpenRecord(datagram, out byte type, out byte[] data)) return false;
            if (type != TincDriverConstants.RouterPacketType) return false;
            plaintext = data;
            return true;
        }

        /// <summary>
        /// Opens an incoming UDP data datagram into its record type + payload. Strips the 12-byte relay header
        /// (DSTID‖SRCID), checks the SRCID is the peer's node id, then decrypts the SPTPS record. Returns <c>false</c> (no
        /// exception) on a short datagram, a foreign SRCID, or an AEAD/replay failure. The caller dispatches by type
        /// (0 = router IP packet, <c>PKT_PROBE</c> = a UDP probe request/reply).
        /// </summary>
        public bool TryOpenRecord(ReadOnlySpan<byte> datagram, out byte type, out byte[] data)
        {
            type = 0;
            data = Array.Empty<byte>();
            int idLen = TincDriverConstants.NodeIdLength;
            if (datagram.Length < idLen + idLen) return false;

            // SRCID (the second id) must be the peer's node id; DSTID (the first) is the null id for a direct packet
            // (we do not relay, so we ignore intermediate-relay cases).
            ReadOnlySpan<byte> srcId = datagram.Slice(idLen, idLen);
            if (!srcId.SequenceEqual(_peerNodeId)) return false;

            ReadOnlySpan<byte> record = datagram.Slice(idLen + idLen);
            SptpsDecodeResult result;
            lock (_sync) result = _record.Decode(record, out type, out data);
            if (result != SptpsDecodeResult.Ok) return false;

            lock (_sync) _receivedPacketCount++;
            return true;
        }
    }
}
