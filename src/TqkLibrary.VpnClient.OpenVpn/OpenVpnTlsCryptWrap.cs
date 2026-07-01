using System.Buffers.Binary;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Crypto;

namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// <c>--tls-crypt</c>: authenticates <em>and</em> encrypts every control-channel packet with the shared
    /// <see cref="OpenVpnStaticKey"/>. Unlike <c>--tls-auth</c> the algorithms are fixed — HMAC-SHA-256 (32-byte tag)
    /// and AES-256-CTR — and the direction is fixed by role (no <c>key-direction</c>): the client encrypts with key
    /// set 1 and decrypts with set 0, the server the reverse. Wire layout (an encoded packet is
    /// <c>op(1) | session_id(8) | body</c>):
    /// <code>
    ///   op(1) | session_id(8) | packet_id(4) | net_time(4) | tag(32) | E(body)
    ///   tag = HMAC-SHA256(Ka, op | session_id | packet_id | net_time | body)
    ///   E   = AES-256-CTR(Kc, IV = tag[0..16], body)
    /// </code>
    /// The header + packet-id are authenticated in the clear; only the body (acks, control packet-id, TLS fragment) is
    /// encrypted. The 128-bit AES-CTR IV is the first half of the HMAC tag.
    /// </summary>
    public sealed class OpenVpnTlsCryptWrap : IOpenVpnControlWrap
    {
        const int HeaderSize = 9;   // op(1) | session_id(8)
        const int PacketIdSize = 8; // replay_id(4) | net_time(4)
        const int TagSize = 32;     // HMAC-SHA-256
        const int IvSize = 16;      // AES-CTR initial counter = tag[0..16]
        const int CipherKeySize = 32; // AES-256
        const int HmacKeySize = 32;   // HMAC-SHA-256
        const int Overhead = HeaderSize + PacketIdSize + TagSize;

        readonly byte[] _outCipherKey;
        readonly byte[] _outHmacKey;
        readonly byte[] _inCipherKey;
        readonly byte[] _inHmacKey;
        readonly Func<uint> _netTime;
        readonly object _sync = new();
        uint _sendPacketId;

        /// <summary>
        /// Creates the wrap over <paramref name="key"/>. <paramref name="isServer"/> selects the role's key sets
        /// (client ⇒ out = set 1, in = set 0; server ⇒ the reverse). <paramref name="netTime"/> supplies the unix-time
        /// stamp (null ⇒ the system clock; tests inject a fixed one).
        /// </summary>
        public OpenVpnTlsCryptWrap(OpenVpnStaticKey key, bool isServer = false, Func<uint>? netTime = null)
        {
            if (key is null) throw new ArgumentNullException(nameof(key));
            // tls-crypt fixes the direction by role: server = KEY_DIRECTION_NORMAL, client = KEY_DIRECTION_INVERSE.
            (int outKey, int inKey) = isServer ? (0, 1) : (1, 0);
            _outCipherKey = key.CipherKey(outKey, CipherKeySize);
            _outHmacKey = key.HmacKey(outKey, HmacKeySize);
            _inCipherKey = key.CipherKey(inKey, CipherKeySize);
            _inHmacKey = key.HmacKey(inKey, HmacKeySize);
            _netTime = netTime ?? DefaultNetTime;
        }

        /// <inheritdoc/>
        public byte[] Wrap(byte[] controlPacket)
        {
            if (controlPacket is null) throw new ArgumentNullException(nameof(controlPacket));
            if (controlPacket.Length < HeaderSize) throw new ArgumentException("control packet too short", nameof(controlPacket));

            int bodyLen = controlPacket.Length - HeaderSize;
            byte[] packetId = new byte[PacketIdSize];
            lock (_sync) BinaryPrimitives.WriteUInt32BigEndian(packetId.AsSpan(0, 4), ++_sendPacketId);
            BinaryPrimitives.WriteUInt32BigEndian(packetId.AsSpan(4, 4), _netTime());

            byte[] tag = ComputeTag(_outHmacKey, controlPacket, 0, packetId, controlPacket, HeaderSize, bodyLen);

            byte[] wire = new byte[Overhead + bodyLen];
            Array.Copy(controlPacket, 0, wire, 0, HeaderSize);            // op | session_id
            Array.Copy(packetId, 0, wire, HeaderSize, PacketIdSize);      // packet_id | net_time
            Array.Copy(tag, 0, wire, HeaderSize + PacketIdSize, TagSize); // HMAC tag
            AesCtr.Transform(_outCipherKey, tag.AsSpan(0, IvSize),
                controlPacket.AsSpan(HeaderSize, bodyLen), wire.AsSpan(Overhead, bodyLen)); // E(body)
            return wire;
        }

        /// <inheritdoc/>
        public bool TryUnwrap(ReadOnlySpan<byte> wire, out byte[] controlPacket)
        {
            controlPacket = Array.Empty<byte>();
            if (wire.Length < Overhead) return false;

            int bodyLen = wire.Length - Overhead;
            byte[] header = wire.Slice(0, HeaderSize).ToArray();
            byte[] packetId = wire.Slice(HeaderSize, PacketIdSize).ToArray();
            ReadOnlySpan<byte> tag = wire.Slice(HeaderSize + PacketIdSize, TagSize);
            ReadOnlySpan<byte> ciphertext = wire.Slice(Overhead, bodyLen);

            byte[] body = new byte[bodyLen];
            AesCtr.Transform(_inCipherKey, tag.Slice(0, IvSize), ciphertext, body); // CTR is its own inverse

            byte[] expected = ComputeTag(_inHmacKey, header, 0, packetId, body, 0, bodyLen);
            if (!CryptoBytes.FixedTimeEquals(tag, expected)) return false;

            byte[] plain = new byte[HeaderSize + bodyLen];
            Array.Copy(header, 0, plain, 0, HeaderSize);
            Array.Copy(body, 0, plain, HeaderSize, bodyLen);
            controlPacket = plain;
            return true;
        }

        // HMAC over: op | session_id | packet_id | net_time | body. header (op | session_id) and body may live in the
        // same array (Wrap) or in separate arrays (Unwrap).
        static byte[] ComputeTag(byte[] hmacKey, byte[] headerSrc, int headerOffset, byte[] packetId, byte[] bodySrc, int bodyOffset, int bodyLen)
        {
            using IncrementalHash h = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, hmacKey);
            h.AppendData(headerSrc, headerOffset, HeaderSize);
            h.AppendData(packetId, 0, PacketIdSize);
            h.AppendData(bodySrc, bodyOffset, bodyLen);
            return h.GetHashAndReset();
        }

        static uint DefaultNetTime() => (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    }
}
