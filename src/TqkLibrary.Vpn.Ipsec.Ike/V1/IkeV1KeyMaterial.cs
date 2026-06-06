using System.Security.Cryptography;
using TqkLibrary.Vpn.Crypto;
using TqkLibrary.Vpn.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.Vpn.Ipsec.Ike.V1
{
    /// <summary>
    /// IKEv1 Main Mode key material with pre-shared-key authentication (RFC 2409 §5):
    /// <c>SKEYID = prf(PSK, Ni|Nr)</c>, then SKEYID_d/a/e keyed by SKEYID over <c>g^xy|CKY-I|CKY-R|n</c>, the
    /// encryption key expanded from SKEYID_e, and the first Phase-1 IV = <c>hash(g^xi|g^xr)</c>.
    /// </summary>
    public sealed class IkeV1KeyMaterial
    {
        IkeV1KeyMaterial(byte[] skeyid, byte[] skeyidD, byte[] skeyidA, byte[] skeyidE, byte[] cipherKey, byte[] initialIv)
        {
            Skeyid = skeyid; SkeyidD = skeyidD; SkeyidA = skeyidA; SkeyidE = skeyidE; CipherKey = cipherKey; InitialIv = initialIv;
        }

        /// <summary>SKEYID — the root key authenticating the exchange.</summary>
        public byte[] Skeyid { get; }

        /// <summary>SKEYID_d — derives Phase 2 (IPsec) keying material.</summary>
        public byte[] SkeyidD { get; }

        /// <summary>SKEYID_a — keys the Phase 2 HASH(1/2/3) and integrity.</summary>
        public byte[] SkeyidA { get; }

        /// <summary>SKEYID_e — derives the Phase 1 encryption key.</summary>
        public byte[] SkeyidE { get; }

        /// <summary>The Phase 1 cipher key (expanded from SKEYID_e to the negotiated length).</summary>
        public byte[] CipherKey { get; }

        /// <summary>The IV for the first encrypted Main Mode message.</summary>
        public byte[] InitialIv { get; }

        /// <summary>Derives the Main Mode key set for a PSK exchange.</summary>
        public static IkeV1KeyMaterial DeriveMainMode(
            HashAlgorithmName hash,
            byte[] preSharedKey,
            byte[] nonceInitiator,
            byte[] nonceResponder,
            byte[] sharedSecret,
            byte[] cookieInitiator,
            byte[] cookieResponder,
            byte[] keInitiator,
            byte[] keResponder,
            int cipherKeyLength,
            int blockSize)
        {
            var prf = new HmacPrf(hash);
            byte[] skeyid = Prf(prf, preSharedKey, Concat(nonceInitiator, nonceResponder));
            byte[] skeyidD = Prf(prf, skeyid, Concat(sharedSecret, cookieInitiator, cookieResponder, new byte[] { 0 }));
            byte[] skeyidA = Prf(prf, skeyid, Concat(skeyidD, sharedSecret, cookieInitiator, cookieResponder, new byte[] { 1 }));
            byte[] skeyidE = Prf(prf, skeyid, Concat(skeyidA, sharedSecret, cookieInitiator, cookieResponder, new byte[] { 2 }));

            byte[] cipherKey = ExpandKey(prf, skeyidE, cipherKeyLength);
            byte[] initialIv = HashBytes(hash, Concat(keInitiator, keResponder));
            byte[] iv = new byte[blockSize];
            Buffer.BlockCopy(initialIv, 0, iv, 0, Math.Min(blockSize, initialIv.Length));

            return new IkeV1KeyMaterial(skeyid, skeyidD, skeyidA, skeyidE, cipherKey, iv);
        }

        /// <summary>Expands SKEYID_e into a key of <paramref name="length"/> bytes (RFC 2409 Appendix B).</summary>
        public static byte[] ExpandKey(IPrf prf, byte[] skeyidE, int length)
        {
            if (skeyidE.Length >= length)
            {
                byte[] truncated = new byte[length];
                Buffer.BlockCopy(skeyidE, 0, truncated, 0, length);
                return truncated;
            }

            var blocks = new List<byte>();
            byte[] previous = Prf(prf, skeyidE, new byte[] { 0 }); // K1 = prf(SKEYID_e, 0)
            blocks.AddRange(previous);
            while (blocks.Count < length)
            {
                previous = Prf(prf, skeyidE, previous);
                blocks.AddRange(previous);
            }
            return blocks.GetRange(0, length).ToArray();
        }

        static byte[] Prf(IPrf prf, byte[] key, byte[] data)
        {
            byte[] output = new byte[prf.OutputSizeInBytes];
            prf.Compute(key, data, output);
            return output;
        }

        internal static byte[] HashBytes(HashAlgorithmName name, byte[] data)
        {
            using HashAlgorithm algorithm = Create(name);
            return algorithm.ComputeHash(data);
        }

        static HashAlgorithm Create(HashAlgorithmName name) => name.Name switch
        {
            "MD5" => MD5.Create(),
            "SHA1" => SHA1.Create(),
            "SHA256" => SHA256.Create(),
            _ => throw new NotSupportedException($"Unsupported IKEv1 hash '{name.Name}'."),
        };

        internal static byte[] Concat(params byte[][] parts)
        {
            int total = 0;
            foreach (byte[] part in parts) total += part.Length;
            byte[] result = new byte[total];
            int offset = 0;
            foreach (byte[] part in parts)
            {
                Buffer.BlockCopy(part, 0, result, offset, part.Length);
                offset += part.Length;
            }
            return result;
        }
    }
}
