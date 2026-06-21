using System.Buffers.Binary;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.OpenVpn.Enums;

namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// The OpenVPN non-AEAD (CBC + HMAC) data channel — the cipher mode an NCP-less server uses (e.g. SoftEther's
    /// OpenVPN function, which pushes no <c>cipher</c> and runs AES-128-CBC + <c>--auth SHA1</c>). Re-implemented from
    /// the OpenVPN data-channel format (spec/behaviour, not copied from GPL source). Wire layout of a P_DATA_V2 packet:
    /// <code>
    ///   op|key_id (1) | peer_id (3) | HMAC(auth) | IV (blocksize) | ciphertext
    ///   ciphertext = AES-CBC( cipher_key, IV, PKCS7( packet_id (4) ‖ payload ) )
    ///   HMAC       = HMAC( hmac_key, IV ‖ ciphertext )                     (full digest, prepended)
    /// </code>
    /// The 4-byte packet-id lives <em>inside</em> the encrypted envelope (the IV is random per packet, so the id is not
    /// the nonce as it is in AEAD); the receiver verifies the HMAC first (constant-time), decrypts, then runs the same
    /// 64-packet sliding <see cref="AntiReplayWindow"/>. The op/peer-id header is outside the MAC (it is the cleartext
    /// routing header, as in <see cref="OpenVpnDataChannel"/>).
    /// </summary>
    public sealed class OpenVpnCbcDataChannel : IOpenVpnDataChannel
    {
        const int OpcodeSize = 1;
        const int PeerIdSize = 3;
        const int PacketIdSize = 4;
        const int V2HeaderSize = OpcodeSize + PeerIdSize;   // op|key_id + peer_id (P_DATA_V2 routing header)
        const int V1HeaderSize = OpcodeSize;                // op|key_id only (P_DATA_V1, no peer-id)
        const int BlockSize = 16;                           // AES block size (the CBC IV length)

        readonly OpenVpnCbcDataKeys _keys;
        readonly IBlockCipher _cipher;
        readonly IIntegrityAlgo _integrity;
        readonly bool _dataV2;                              // send P_DATA_V2 (peer-id) vs P_DATA_V1 (no peer-id)
        readonly int _sendHeaderSize;
        readonly byte _opcodeByte;
        readonly uint _peerId;                              // 24-bit, stamped on outgoing V2 packets (0 until pushed)
        readonly AntiReplayWindow _replay = new();
        readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        readonly object _sync = new();
        uint _sendPacketId;                                 // last used; the first outbound packet is 1

        /// <summary>
        /// Creates the CBC data channel over <paramref name="keys"/> with the block <paramref name="cipher"/> (AES-CBC)
        /// and the <paramref name="integrity"/> MAC (<c>--auth</c>, e.g. HMAC-SHA1). <paramref name="keyId"/> tags
        /// outgoing packets; <paramref name="peerId"/> is the server-assigned 24-bit peer-id (0 until a PUSH_REPLY
        /// supplies one). <paramref name="dataV2"/> selects the wire format: P_DATA_V2 (a 3-byte peer-id, the modern
        /// default) when the peer negotiated a peer-id, or P_DATA_V1 (no peer-id) for an older server (e.g. SoftEther's
        /// OpenVPN function). Inbound packets are accepted in <em>either</em> format regardless.
        /// </summary>
        public OpenVpnCbcDataChannel(OpenVpnCbcDataKeys keys, IBlockCipher cipher, IIntegrityAlgo integrity,
            byte keyId = 0, uint peerId = 0, bool dataV2 = true)
        {
            _keys = keys ?? throw new ArgumentNullException(nameof(keys));
            _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
            _integrity = integrity ?? throw new ArgumentNullException(nameof(integrity));
            if (cipher.BlockSizeInBytes != BlockSize) throw new ArgumentException("CBC data channel expects a 16-byte block cipher.", nameof(cipher));
            if (peerId > 0xFFFFFF) throw new ArgumentOutOfRangeException(nameof(peerId), "peer-id is 24-bit.");
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

        /// <inheritdoc/>
        public uint SentPacketCount { get { lock (_sync) return _sendPacketId; } }

        /// <inheritdoc/>
        public byte[] Protect(ReadOnlySpan<byte> plaintext)
        {
            uint packetId;
            lock (_sync) packetId = checked(++_sendPacketId); // overflow ⇒ rekey before reuse (handled by the data plane)

            // inner = packet_id (4) ‖ payload, PKCS7-padded to a whole number of blocks.
            int innerLen = PacketIdSize + plaintext.Length;
            int pad = BlockSize - (innerLen % BlockSize);      // PKCS7 always adds 1..BlockSize bytes
            int ctLen = innerLen + pad;
            byte[] padded = new byte[ctLen];
            BinaryPrimitives.WriteUInt32BigEndian(padded.AsSpan(0, PacketIdSize), packetId);
            plaintext.CopyTo(padded.AsSpan(PacketIdSize));
            for (int i = innerLen; i < ctLen; i++) padded[i] = (byte)pad;

            int icvLen = _integrity.IcvSizeInBytes;
            int hdr = _sendHeaderSize;
            byte[] wire = new byte[hdr + icvLen + BlockSize + ctLen];
            wire[0] = _opcodeByte;
            if (_dataV2) WriteUInt24BigEndian(wire.AsSpan(OpcodeSize, PeerIdSize), _peerId);

            // IV (random) sits right after the MAC; the ciphertext follows.
            int ivOffset = hdr + icvLen;
            byte[] iv = new byte[BlockSize];
            _rng.GetBytes(iv);
            iv.CopyTo(wire.AsSpan(ivOffset));
            _cipher.Encrypt(_keys.SendCipherKey, iv, padded, wire.AsSpan(ivOffset + BlockSize, ctLen));

            // HMAC over the encrypted envelope (IV ‖ ciphertext), prepended.
            _integrity.ComputeIcv(_keys.SendHmacKey, wire.AsSpan(ivOffset), wire.AsSpan(hdr, icvLen));
            return wire;
        }

        /// <inheritdoc/>
        public bool TryUnprotect(ReadOnlySpan<byte> wire, out byte[] plaintext)
        {
            plaintext = Array.Empty<byte>();
            if (wire.Length < 1) return false;
            int hdr = InboundHeaderSize(wire[0]);                 // V2 (peer-id) or V1 (none); -1 ⇒ not a data packet
            if (hdr < 0) return false;
            int icvLen = _integrity.IcvSizeInBytes;
            // header + MAC + IV + at least one ciphertext block
            if (wire.Length < hdr + icvLen + BlockSize + BlockSize) return false;

            ReadOnlySpan<byte> envelope = wire.Slice(hdr + icvLen);   // IV ‖ ciphertext
            int ctLen = envelope.Length - BlockSize;
            if (ctLen <= 0 || ctLen % BlockSize != 0) return false;

            // Verify the HMAC over the envelope (constant-time) before touching the ciphertext.
            Span<byte> expected = stackalloc byte[icvLen];
            _integrity.ComputeIcv(_keys.ReceiveHmacKey, envelope, expected);
            if (!FixedTimeEquals(wire.Slice(hdr, icvLen), expected)) return false;

            byte[] padded = new byte[ctLen];
            _cipher.Decrypt(_keys.ReceiveCipherKey, envelope.Slice(0, BlockSize), envelope.Slice(BlockSize), padded);

            // Strip PKCS7 padding (validate every pad byte).
            int pad = padded[ctLen - 1];
            if (pad < 1 || pad > BlockSize || pad > ctLen) return false;
            for (int i = ctLen - pad; i < ctLen; i++) if (padded[i] != pad) return false;
            int innerLen = ctLen - pad;
            if (innerLen < PacketIdSize) return false;

            uint packetId = BinaryPrimitives.ReadUInt32BigEndian(padded.AsSpan(0, PacketIdSize));
            lock (_sync) { if (!_replay.Check(packetId)) return false; }

            byte[] pt = new byte[innerLen - PacketIdSize];
            Array.Copy(padded, PacketIdSize, pt, 0, pt.Length);
            lock (_sync) _replay.Commit(packetId);
            plaintext = pt;
            return true;
        }

        static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        static void WriteUInt24BigEndian(Span<byte> destination, uint value)
        {
            destination[0] = (byte)(value >> 16);
            destination[1] = (byte)(value >> 8);
            destination[2] = (byte)value;
        }
    }
}
