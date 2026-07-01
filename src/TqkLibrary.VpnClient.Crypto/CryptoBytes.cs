using System;
#if NET5_0_OR_GREATER
using System.Security.Cryptography;
#endif

namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// Shared constant-time byte helpers. Centralizes the XOR-accumulate comparison that was
    /// previously duplicated across IKE/ESP, WireGuard, ZeroTier, Tinc, OpenVPN and SSH codecs.
    /// </summary>
    public static class CryptoBytes
    {
        /// <summary>
        /// Compares two byte spans for equality without branching on their contents
        /// (constant-time with respect to the data), so a caller does not leak secrets via timing.
        /// Returns <see langword="false"/> when the lengths differ.
        /// On net5.0+ this delegates to <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>;
        /// on netstandard2.0 it falls back to an XOR-accumulate loop.
        /// </summary>
        public static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
#if NET5_0_OR_GREATER
            return CryptographicOperations.FixedTimeEquals(a, b);
#else
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
#endif
        }
    }
}
