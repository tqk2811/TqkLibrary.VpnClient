using System.Security.Cryptography;
using TqkLibrary.Vpn.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.Vpn.Crypto
{
    /// <summary>HMAC integrity with a truncated ICV (e.g. HMAC-SHA256-128 for ESP/IKE).</summary>
    public sealed class HmacIntegrity : IIntegrityAlgo
    {
        readonly HashAlgorithmName _hash;

        /// <summary>Creates an integrity algorithm over <paramref name="hash"/> with the given key/ICV sizes.</summary>
        public HmacIntegrity(HashAlgorithmName hash, int keySizeInBytes, int icvSizeInBytes)
        {
            _hash = hash;
            KeySizeInBytes = keySizeInBytes;
            IcvSizeInBytes = icvSizeInBytes;
        }

        /// <inheritdoc/>
        public int KeySizeInBytes { get; }

        /// <inheritdoc/>
        public int IcvSizeInBytes { get; }

        /// <inheritdoc/>
        public void ComputeIcv(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> icv)
        {
            byte[] mac = HmacUtil.Compute(_hash, key.ToArray(), data.ToArray());
            mac.AsSpan(0, IcvSizeInBytes).CopyTo(icv);
        }

        /// <summary>HMAC-SHA256-128: 32-byte key, 16-byte ICV (RFC 4868).</summary>
        public static HmacIntegrity HmacSha256_128() => new(HashAlgorithmName.SHA256, 32, 16);

        /// <summary>HMAC-SHA1-96: 20-byte key, 12-byte ICV (RFC 2404).</summary>
        public static HmacIntegrity HmacSha1_96() => new(HashAlgorithmName.SHA1, 20, 12);
    }
}
