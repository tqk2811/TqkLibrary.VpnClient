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
    public sealed class OpenVpnDataChannel
    {
        const int OpcodeSize = 1;
        const int PeerIdSize = 3;
        const int PacketIdSize = 4;
        const int TagSize = 16;
        const int HeaderSize = OpcodeSize + PeerIdSize;          // op|key_id + peer_id  (also the AAD prefix)
        const int AadSize = HeaderSize + PacketIdSize;           // = nonce-relevant cleartext header
        const int Overhead = HeaderSize + PacketIdSize + TagSize;
        const int NonceSize = 12;

        readonly OpenVpnDataChannelKeys _keys;
        readonly IAeadCipher _cipher;
        readonly byte _opcodeByte;
        readonly uint _peerId; // 24-bit, stamped on outgoing packets (server-assigned; 0 until pushed)
        readonly AntiReplayWindow _replay = new();
        readonly object _sync = new();
        uint _sendPacketId; // last used; the first outbound packet is 1

        /// <summary>
        /// Creates the data channel over <paramref name="keys"/>. <paramref name="keyId"/> tags outgoing packets (the
        /// current key generation); <paramref name="peerId"/> is the server-assigned 24-bit peer-id (0 until a
        /// PUSH_REPLY supplies one); <paramref name="cipher"/> defaults to AES-256-GCM.
        /// </summary>
        public OpenVpnDataChannel(OpenVpnDataChannelKeys keys, byte keyId = 0, uint peerId = 0, IAeadCipher? cipher = null)
        {
            _keys = keys ?? throw new ArgumentNullException(nameof(keys));
            if (peerId > 0xFFFFFF) throw new ArgumentOutOfRangeException(nameof(peerId), "peer-id is 24-bit.");
            _cipher = cipher ?? new AesGcmCipher(OpenVpnDataChannelKeys.CipherKeySize);
            _opcodeByte = OpenVpnPacketCodec.Header(OpenVpnOpcode.DataV2, keyId);
            _peerId = peerId;
        }

        /// <summary>The next outbound packet-id (the count of packets protected so far).</summary>
        public uint SentPacketCount { get { lock (_sync) return _sendPacketId; } }

        /// <summary>Seals an outgoing tunnelled packet into a P_DATA_V2 datagram.</summary>
        public byte[] Protect(ReadOnlySpan<byte> plaintext)
        {
            uint packetId;
            lock (_sync) packetId = checked(++_sendPacketId); // overflow ⇒ must rekey before reusing a nonce

            byte[] wire = new byte[Overhead + plaintext.Length];
            wire[0] = _opcodeByte;
            WriteUInt24BigEndian(wire.AsSpan(OpcodeSize, PeerIdSize), _peerId);
            BinaryPrimitives.WriteUInt32BigEndian(wire.AsSpan(HeaderSize, PacketIdSize), packetId);

            Span<byte> nonce = stackalloc byte[NonceSize];
            BinaryPrimitives.WriteUInt32BigEndian(nonce.Slice(0, PacketIdSize), packetId);
            _keys.SendImplicitIv.CopyTo(nonce.Slice(PacketIdSize));

            // AAD = the cleartext header (op|key_id, peer_id, packet_id); tag sits before the ciphertext.
            _cipher.Seal(_keys.SendCipherKey, nonce, plaintext, wire.AsSpan(0, AadSize),
                wire.AsSpan(Overhead), wire.AsSpan(AadSize, TagSize));
            return wire;
        }

        /// <summary>
        /// Opens an incoming P_DATA_V2 datagram into the tunnelled packet. Returns false if it is not a data packet,
        /// is truncated, fails authentication, or is a replay.
        /// </summary>
        public bool TryUnprotect(ReadOnlySpan<byte> wire, out byte[] plaintext)
        {
            plaintext = Array.Empty<byte>();
            if (wire.Length < Overhead) return false;
            if (OpenVpnPacketCodec.ReadOpcode(wire[0]) != OpenVpnOpcode.DataV2) return false;

            uint packetId = BinaryPrimitives.ReadUInt32BigEndian(wire.Slice(HeaderSize, PacketIdSize));
            lock (_sync) { if (!_replay.Check(packetId)) return false; }

            Span<byte> nonce = stackalloc byte[NonceSize];
            BinaryPrimitives.WriteUInt32BigEndian(nonce.Slice(0, PacketIdSize), packetId);
            _keys.ReceiveImplicitIv.CopyTo(nonce.Slice(PacketIdSize));

            byte[] pt = new byte[wire.Length - Overhead];
            bool ok = _cipher.Open(_keys.ReceiveCipherKey, nonce, wire.Slice(Overhead), wire.Slice(AadSize, TagSize),
                wire.Slice(0, AadSize), pt);
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
