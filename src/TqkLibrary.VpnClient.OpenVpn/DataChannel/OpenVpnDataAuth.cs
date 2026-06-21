using System.Security.Cryptography;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// Maps an OpenVPN <c>--auth</c> algorithm name to the HMAC the non-AEAD data channel uses to authenticate each
    /// packet. OpenVPN's data-channel HMAC is the <b>full</b> digest (not truncated like ESP's HMAC-SHA1-96), and the
    /// HMAC key length equals the digest size. Default is HMAC-SHA1 (OpenVPN's <c>--auth</c> default).
    /// </summary>
    public static class OpenVpnDataAuth
    {
        /// <summary>The HMAC key / ICV length in bytes for <paramref name="auth"/> (the digest size); SHA1 when unknown/empty.</summary>
        public static int KeySizeBytes(string? auth) => DigestSize(auth);

        /// <summary>Builds the full-digest HMAC integrity algorithm for <paramref name="auth"/> (key size = ICV size = digest size).</summary>
        public static IIntegrityAlgo CreateIntegrity(string? auth)
        {
            int size = DigestSize(auth);
            return new HmacIntegrity(HashName(auth), size, size);
        }

        static HashAlgorithmName HashName(string? auth) => auth?.ToUpperInvariant() switch
        {
            "SHA256" => HashAlgorithmName.SHA256,
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            "MD5" => HashAlgorithmName.MD5,
            _ => HashAlgorithmName.SHA1, // OpenVPN's --auth default
        };

        static int DigestSize(string? auth) => auth?.ToUpperInvariant() switch
        {
            "SHA256" => 32,
            "SHA384" => 48,
            "SHA512" => 64,
            "MD5" => 16,
            _ => 20, // SHA1
        };
    }
}
