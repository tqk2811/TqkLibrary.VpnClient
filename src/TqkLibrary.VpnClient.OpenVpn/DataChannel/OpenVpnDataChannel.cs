using System.Buffers.Binary;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Aead;
using TqkLibrary.VpnClient.OpenVpn.Enums;

namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// The OpenVPN AEAD data channel (P_DATA_V2 + AES-256-GCM) running on the keys derived from key-method-2
    /// (<see cref="OpenVpnDataChannelKeys"/>). <see cref="Protect"/> wraps a tunnelled IP packet, <see cref="TryUnprotect"/>
    /// recovers one (returning false on a bad tag or a replayed packet-id). Wire layout:
    /// <code>
    ///   op|key_id (1) | peer_id (3) | packet_id (4) | auth_tag (16) | ciphertext
    ///   nonce (12) = packet_id (4) ‖ implicit_iv (8)
    ///   AAD        = op|key_id (1) | peer_id (3) | packet_id (4)   (the cleartext header)
    /// </code>
    /// The packet-id is the per-key monotonic counter and the low 4 bytes of the GCM nonce; it must never repeat for a
    /// key, so the sender's counter overflowing throws (a soft-reset/rekey must replace the channel first — V2.e). The
    /// receiver runs a 64-packet sliding <see cref="AntiReplayWindow"/>.
    /// </summary>
    public sealed class OpenVpnDataChannel : IOpenVpnDataChannel
    {
        const int OpcodeSize = 1;
        const int PeerIdSize = 3;
        const int PacketIdSize = 4;
        const int TagSize = 16;
        const int V2HeaderSize = OpcodeSize + PeerIdSize;        // op|key_id + peer_id (P_DATA_V2 cleartext header)
        const int V1HeaderSize = OpcodeSize;                     // op|key_id only (P_DATA_V1, no peer-id)
        const int NonceSize = 12;

        readonly OpenVpnDataChannelKeys _keys;
        readonly IAeadCipher _cipher;
        readonly bool _dataV2;                                   // send P_DATA_V2 (peer-id) vs P_DATA_V1 (no peer-id)
        readonly int _sendHeaderSize;
        readonly byte _opcodeByte;
        readonly uint _peerId; // 24-bit, stamped on outgoing V2 packets (server-assigned; 0 until pushed)
        readonly AntiReplayWindow _replay = new();
        readonly object _sync = new();
        uint _sendPacketId; // last used; the first outbound packet is 1

        /// <summary>
        /// Creates the data channel over <paramref name="keys"/>. <paramref name="keyId"/> tags outgoing packets (the
        /// current key generation); <paramref name="peerId"/> is the server-assigned 24-bit peer-id (0 until a
        /// PUSH_REPLY supplies one); <paramref name="cipher"/> defaults to AES-GCM sized to the key (128/256).
        /// <paramref name="dataV2"/> selects the wire format: P_DATA_V2 (a 3-byte peer-id, the modern default) when a
        /// peer-id was negotiated, or P_DATA_V1 (no peer-id) for an older server; inbound packets are accepted in either.
        /// </summary>
        public OpenVpnDataChannel(OpenVpnDataChannelKeys keys, byte keyId = 0, uint peerId = 0, IAeadCipher? cipher = null, bool dataV2 = true)
        {
            _keys = keys ?? throw new ArgumentNullException(nameof(keys));
            if (peerId > 0xFFFFFF) throw new ArgumentOutOfRangeException(nameof(peerId), "peer-id is 24-bit.");
            // Default AEAD matches the negotiated key length (AES-128/256-GCM); pass an explicit cipher for others.
            _cipher = cipher ?? new AesGcmCipher(keys.SendCipherKey.Length);
            _dataV2 = dataV2;
            _sendHeaderSize = dataV2 ? V2HeaderSize : V1HeaderSize;
            _opcodeByte = OpenVpnPacketCodec.Header(dataV2 ? OpenVpnOpcode.DataV2 : OpenVpnOpcode.DataV1, keyId);
            _peerId = peerId;
        }

        // The routing-header size for an inbound packet, by its opcode (V2 carries a 3-byte peer-id, V1 does not), or -1
        // when it is not a data packet.
        static int InboundHeaderSize(byte first) => OpenVpnPacketCodec.ReadOpcode(first) switch
        {
            OpenVpnOpcode.DataV2 => V2HeaderSize,
            OpenVpnOpcode.DataV1 => V1HeaderSize,
            _ => -1,
        };

        /// <summary>The next outbound packet-id (the count of packets protected so far).</summary>
        public uint SentPacketCount { get { lock (_sync) return _sendPacketId; } }

        /// <summary>Seals an outgoing tunnelled packet into a P_DATA_V2 datagram.</summary>
        public byte[] Protect(ReadOnlySpan<byte> plaintext)
        {
            uint packetId;
            lock (_sync) packetId = checked(++_sendPacketId); // overflow ⇒ must rekey before reusing a nonce

            int hdr = _sendHeaderSize;
            int aadSize = hdr + PacketIdSize;
            int overhead = aadSize + TagSize;
            byte[] wire = new byte[overhead + plaintext.Length];
            wire[0] = _opcodeByte;
            if (_dataV2) WriteUInt24BigEndian(wire.AsSpan(OpcodeSize, PeerIdSize), _peerId);
            BinaryPrimitives.WriteUInt32BigEndian(wire.AsSpan(hdr, PacketIdSize), packetId);

            Span<byte> nonce = stackalloc byte[NonceSize];
            BinaryPrimitives.WriteUInt32BigEndian(nonce.Slice(0, PacketIdSize), packetId);
            _keys.SendImplicitIv.CopyTo(nonce.Slice(PacketIdSize));

            // AAD = the cleartext header (op|key_id, [peer_id], packet_id); tag sits before the ciphertext.
            _cipher.Seal(_keys.SendCipherKey, nonce, plaintext, wire.AsSpan(0, aadSize),
                wire.AsSpan(overhead), wire.AsSpan(aadSize, TagSize));
            return wire;
        }

        /// <summary>
        /// Opens an incoming P_DATA_V2 datagram into the tunnelled packet. Returns false if it is not a data packet,
        /// is truncated, fails authentication, or is a replay.
        /// </summary>
        public bool TryUnprotect(ReadOnlySpan<byte> wire, out byte[] plaintext)
        {
            plaintext = Array.Empty<byte>();
            if (wire.Length < 1) return false;
            int hdr = InboundHeaderSize(wire[0]);            // V2 (peer-id) or V1 (none); -1 ⇒ not a data packet
            if (hdr < 0) return false;
            int aadSize = hdr + PacketIdSize;
            int overhead = aadSize + TagSize;
            if (wire.Length < overhead) return false;

            uint packetId = BinaryPrimitives.ReadUInt32BigEndian(wire.Slice(hdr, PacketIdSize));
            lock (_sync) { if (!_replay.Check(packetId)) return false; }

            Span<byte> nonce = stackalloc byte[NonceSize];
            BinaryPrimitives.WriteUInt32BigEndian(nonce.Slice(0, PacketIdSize), packetId);
            _keys.ReceiveImplicitIv.CopyTo(nonce.Slice(PacketIdSize));

            byte[] pt = new byte[wire.Length - overhead];
            bool ok = _cipher.Open(_keys.ReceiveCipherKey, nonce, wire.Slice(overhead), wire.Slice(aadSize, TagSize),
                wire.Slice(0, aadSize), pt);
            if (!ok) return false;

            lock (_sync) _replay.Commit(packetId);
            plaintext = pt;
            return true;
        }

        static void WriteUInt24BigEndian(Span<byte> destination, uint value)
        {
            destination[0] = (byte)(value >> 16);
            destination[1] = (byte)(value >> 8);
            destination[2] = (byte)value;
        }
    }
}
