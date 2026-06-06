using System.Security.Cryptography;
using TqkLibrary.Vpn.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.Vpn.Crypto
{
    /// <summary>HMAC-based PRF (e.g. PRF-HMAC-SHA256 for IKEv2 / MS-CHAPv2 key derivation).</summary>
    public sealed class HmacPrf : IPrf
    {
        readonly HashAlgorithmName _hash;

        /// <summary>Creates a PRF over the given HMAC hash.</summary>
        public HmacPrf(HashAlgorithmName hash)
        {
            _hash = hash;
            OutputSizeInBytes = HmacUtil.OutputSize(hash);
        }

        /// <inheritdoc/>
        public int OutputSizeInBytes { get; }

        /// <inheritdoc/>
        public void Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> seed, Span<byte> output)
        {
            byte[] mac = HmacUtil.Compute(_hash, key.ToArray(), seed.ToArray());
            mac.AsSpan(0, OutputSizeInBytes).CopyTo(output);
        }

        /// <summary>PRF-HMAC-SHA256 (RFC 4868).</summary>
        public static HmacPrf Sha256() => new(HashAlgorithmName.SHA256);
    }
}
