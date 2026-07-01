using System.Buffers.Binary;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.OpenVpn.Enums;

namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// <c>--tls-auth</c>: HMAC-authenticates every control-channel packet with the shared <see cref="OpenVpnStaticKey"/>
    /// (the bytes stay in the clear). It also prepends a replay packet-id + timestamp, which are folded into the HMAC.
    /// Wire layout (an encoded packet is <c>op(1) | session_id(8) | body</c>):
    /// <code>
    ///   op(1) | session_id(8) | HMAC(N) | replay_id(4) | net_time(4) | body
    ///   HMAC = HMAC_hash(Kout, replay_id | net_time | op | session_id | body)
    /// </code>
    /// The HMAC key is the first <c>hash</c>-output-size bytes of the direction's HMAC key set; <c>hash</c> defaults to
    /// SHA1 (OpenVPN's <c>--auth</c> default). The client uses <see cref="OpenVpnKeyDirection.Inverse"/> (or
    /// <see cref="OpenVpnKeyDirection.Bidirectional"/> when the profile omits <c>key-direction</c>).
    /// </summary>
    public sealed class OpenVpnTlsAuthWrap : IOpenVpnControlWrap
    {
        const int ReplayIdSize = 4;
        const int NetTimeSize = 4;
        const int MetaSize = ReplayIdSize + NetTimeSize; // replay_id(4) | net_time(4)
        const int HeaderSize = 9; // op(1) | session_id(8)

        readonly HashAlgorithmName _hash;
        readonly int _tagSize;
        readonly byte[] _outKey;
        readonly byte[] _inKey;
        readonly Func<uint> _netTime;
        readonly object _sync = new();
        uint _sendPacketId;

        /// <summary>
        /// Creates the wrap over <paramref name="key"/>. <paramref name="direction"/> selects the out/in HMAC key sets
        /// (client: <see cref="OpenVpnKeyDirection.Inverse"/>, or <see cref="OpenVpnKeyDirection.Bidirectional"/>).
        /// <paramref name="hash"/> is the HMAC digest (null ⇒ SHA1). <paramref name="netTime"/> supplies the unix-time
        /// stamp (null ⇒ the system clock; tests inject a fixed one).
        /// </summary>
        public OpenVpnTlsAuthWrap(OpenVpnStaticKey key, OpenVpnKeyDirection direction,
            HashAlgorithmName? hash = null, Func<uint>? netTime = null)
        {
            if (key is null) throw new ArgumentNullException(nameof(key));
            _hash = hash ?? HashAlgorithmName.SHA1;
            _tagSize = HmacOutputSize(_hash);
            (int outKey, int inKey) = OpenVpnStaticKey.ResolveDirection(direction);
            _outKey = key.HmacKey(outKey, _tagSize);
            _inKey = key.HmacKey(inKey, _tagSize);
            _netTime = netTime ?? DefaultNetTime;
        }

        /// <inheritdoc/>
        public byte[] Wrap(byte[] controlPacket)
        {
            if (controlPacket is null) throw new ArgumentNullException(nameof(controlPacket));
            if (controlPacket.Length < HeaderSize) throw new ArgumentException("control packet too short", nameof(controlPacket));

            int bodyLen = controlPacket.Length - HeaderSize;
            byte[] meta = new byte[MetaSize];
            lock (_sync) BinaryPrimitives.WriteUInt32BigEndian(meta.AsSpan(0, 4), ++_sendPacketId);
            BinaryPrimitives.WriteUInt32BigEndian(meta.AsSpan(4, 4), _netTime());

            byte[] tag = ComputeTag(_outKey, meta, controlPacket, 0, controlPacket, HeaderSize, bodyLen);

            byte[] wire = new byte[HeaderSize + _tagSize + MetaSize + bodyLen];
            Array.Copy(controlPacket, 0, wire, 0, HeaderSize);                 // op | session_id
            Array.Copy(tag, 0, wire, HeaderSize, _tagSize);                    // HMAC
            Array.Copy(meta, 0, wire, HeaderSize + _tagSize, MetaSize);        // replay_id | net_time
            Array.Copy(controlPacket, HeaderSize, wire, HeaderSize + _tagSize + MetaSize, bodyLen); // body
            return wire;
        }

        /// <inheritdoc/>
        public bool TryUnwrap(ReadOnlySpan<byte> wire, out byte[] controlPacket)
        {
            controlPacket = Array.Empty<byte>();
            int overhead = HeaderSize + _tagSize + MetaSize;
            if (wire.Length < overhead) return false;

            int bodyLen = wire.Length - overhead;
            ReadOnlySpan<byte> header = wire.Slice(0, HeaderSize);
            ReadOnlySpan<byte> tag = wire.Slice(HeaderSize, _tagSize);
            byte[] meta = wire.Slice(HeaderSize + _tagSize, MetaSize).ToArray();
            byte[] body = wire.Slice(overhead, bodyLen).ToArray();

            byte[] expected = ComputeTag(_inKey, meta, header.ToArray(), 0, body, 0, bodyLen);
            if (!CryptoBytes.FixedTimeEquals(tag, expected)) return false;

            byte[] plain = new byte[HeaderSize + bodyLen];
            header.CopyTo(plain);
            Array.Copy(body, 0, plain, HeaderSize, bodyLen);
            controlPacket = plain;
            return true;
        }

        // HMAC over: meta(replay_id | net_time) | op | session_id | body. The header (op | session_id) and the body
        // may live in the same array (Wrap) or in separate arrays (Unwrap).
        byte[] ComputeTag(byte[] hmacKey, byte[] meta, byte[] headerSrc, int headerOffset, byte[] bodySrc, int bodyOffset, int bodyLen)
        {
            using IncrementalHash h = IncrementalHash.CreateHMAC(_hash, hmacKey);
            h.AppendData(meta, 0, MetaSize);
            h.AppendData(headerSrc, headerOffset, HeaderSize);
            h.AppendData(bodySrc, bodyOffset, bodyLen);
            return h.GetHashAndReset();
        }

        static uint DefaultNetTime() => (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        static int HmacOutputSize(HashAlgorithmName hash) => hash.Name switch
        {
            "MD5" => 16,
            "SHA1" => 20,
            "SHA256" => 32,
            "SHA384" => 48,
            "SHA512" => 64,
            _ => throw new NotSupportedException($"Unsupported tls-auth digest '{hash.Name}'."),
        };
    }
}
