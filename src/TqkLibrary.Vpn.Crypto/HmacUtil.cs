using System.Security.Cryptography;

namespace TqkLibrary.Vpn.Crypto
{
    /// <summary>Internal helper selecting a BCL <see cref="HMAC"/> by <see cref="HashAlgorithmName"/>.</summary>
    internal static class HmacUtil
    {
        public static int OutputSize(HashAlgorithmName hash) => hash.Name switch
        {
            "MD5" => 16,
            "SHA1" => 20,
            "SHA256" => 32,
            "SHA384" => 48,
            "SHA512" => 64,
            _ => throw new NotSupportedException($"Unsupported HMAC hash '{hash.Name}'."),
        };

        public static byte[] Compute(HashAlgorithmName hash, byte[] key, byte[] data)
        {
            using HMAC hmac = Create(hash, key);
            return hmac.ComputeHash(data);
        }

        static HMAC Create(HashAlgorithmName hash, byte[] key) => hash.Name switch
        {
            "MD5" => new HMACMD5(key),
            "SHA1" => new HMACSHA1(key),
            "SHA256" => new HMACSHA256(key),
            "SHA384" => new HMACSHA384(key),
            "SHA512" => new HMACSHA512(key),
            _ => throw new NotSupportedException($"Unsupported HMAC hash '{hash.Name}'."),
        };
    }
}
