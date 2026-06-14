using System.Security.Cryptography;

namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// The TLS 1.0/1.1 pseudo-random function (RFC 2246 §5 / RFC 4346): <c>PRF(secret, label, seed) =
    /// P_MD5(S1, label‖seed) XOR P_SHA1(S2, label‖seed)</c>, where the secret is split into two halves S1/S2 (sharing
    /// the middle byte when its length is odd). A pure, stateless codec. OpenVPN's classic key-method-2 derivation
    /// (master secret + key expansion) uses this PRF when <c>key-derivation tls-ekm</c> is not negotiated.
    /// </summary>
    public static class Tls1Prf
    {
        /// <summary>Expands <paramref name="length"/> bytes from <paramref name="secret"/> over <paramref name="label"/>‖<paramref name="seed"/>.</summary>
        public static byte[] Compute(byte[] secret, byte[] label, byte[] seed, int length)
        {
            if (secret is null) throw new ArgumentNullException(nameof(secret));
            if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));

            byte[] labelSeed = Concat(label ?? Array.Empty<byte>(), seed ?? Array.Empty<byte>());
            int half = (secret.Length + 1) / 2; // ceil: S1/S2 overlap one byte for an odd-length secret.
            byte[] s1 = new byte[half];
            byte[] s2 = new byte[half];
            Array.Copy(secret, 0, s1, 0, half);
            Array.Copy(secret, secret.Length - half, s2, 0, half);

            byte[] md5 = PHash(HashAlgorithmName.MD5, s1, labelSeed, length);
            byte[] sha1 = PHash(HashAlgorithmName.SHA1, s2, labelSeed, length);
            byte[] result = new byte[length];
            for (int i = 0; i < length; i++) result[i] = (byte)(md5[i] ^ sha1[i]);
            return result;
        }

        // P_hash(secret, seed) = HMAC(secret, A(1)‖seed) ‖ HMAC(secret, A(2)‖seed) ‖ … ; A(0)=seed, A(i)=HMAC(secret, A(i-1)).
        static byte[] PHash(HashAlgorithmName hash, byte[] secret, byte[] seed, int length)
        {
            byte[] result = new byte[length];
            int produced = 0;
            using HMAC hmac = Create(hash, secret);
            byte[] a = hmac.ComputeHash(seed); // A(1)
            while (produced < length)
            {
                byte[] block = hmac.ComputeHash(Concat(a, seed)); // HMAC(secret, A(i)‖seed)
                int take = Math.Min(block.Length, length - produced);
                Array.Copy(block, 0, result, produced, take);
                produced += take;
                a = hmac.ComputeHash(a); // A(i+1)
            }
            return result;
        }

        static HMAC Create(HashAlgorithmName hash, byte[] key) => hash.Name switch
        {
            "MD5" => new HMACMD5(key),
            "SHA1" => new HMACSHA1(key),
            _ => throw new NotSupportedException($"Tls1Prf uses MD5/SHA1 only, not '{hash.Name}'."),
        };

        static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            Array.Copy(a, 0, result, 0, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);
            return result;
        }
    }
}
