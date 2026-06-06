using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using TqkLibrary.Vpn.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.Vpn.Crypto
{
    /// <summary>
    /// Classic finite-field Diffie-Hellman over a MODP group (RFC 2409 group 2 / RFC 3526 group 14),
    /// generator g = 2. Public values are fixed-length big-endian (modulus size). Used by IKE.
    /// </summary>
    public sealed class ModpDhGroup : IDhGroup
    {
        // RFC 3526 — 1024-bit MODP (IKE group 2).
        const string Group2Prime =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
            "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
            "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

        // RFC 3526 — 2048-bit MODP (IKE group 14).
        const string Group14Prime =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
            "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
            "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
            "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
            "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
            "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

        readonly BigInteger _p;
        readonly BigInteger _g;
        readonly int _byteLength;

        ModpDhGroup(int groupId, string primeHex)
        {
            GroupId = groupId;
            _p = ParseUnsignedHex(primeHex);
            _g = new BigInteger(2);
            _byteLength = (primeHex.Length / 2);
        }

        /// <inheritdoc/>
        public int GroupId { get; }

        /// <inheritdoc/>
        public int PublicValueSizeInBytes => _byteLength;

        /// <summary>1024-bit MODP group (IKE group 2).</summary>
        public static ModpDhGroup Group2() => new(2, Group2Prime);

        /// <summary>2048-bit MODP group (IKE group 14).</summary>
        public static ModpDhGroup Group14() => new(14, Group14Prime);

        /// <inheritdoc/>
        public byte[] GeneratePrivateKey()
        {
            // A random exponent in [2, p-2].
            byte[] random = new byte[_byteLength];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(random);
            BigInteger value = FromBigEndianUnsigned(random);
            BigInteger priv = (value % (_p - 3)) + 2;
            return ToBigEndianFixed(priv, _byteLength);
        }

        /// <inheritdoc/>
        public byte[] DerivePublicValue(ReadOnlySpan<byte> privateKey)
        {
            BigInteger x = FromBigEndianUnsigned(privateKey);
            BigInteger pub = BigInteger.ModPow(_g, x, _p);
            return ToBigEndianFixed(pub, _byteLength);
        }

        /// <inheritdoc/>
        public byte[] DeriveSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicValue)
        {
            BigInteger x = FromBigEndianUnsigned(privateKey);
            BigInteger peer = FromBigEndianUnsigned(peerPublicValue);
            BigInteger secret = BigInteger.ModPow(peer, x, _p);
            return ToBigEndianFixed(secret, _byteLength);
        }

        static BigInteger ParseUnsignedHex(string hex)
        {
            byte[] be = new byte[hex.Length / 2];
            for (int i = 0; i < be.Length; i++)
                be[i] = byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return FromBigEndianUnsigned(be);
        }

        static BigInteger FromBigEndianUnsigned(ReadOnlySpan<byte> bigEndian)
        {
            // Convert to little-endian and append a 0x00 high byte so the value is treated as positive.
            byte[] le = new byte[bigEndian.Length + 1];
            for (int i = 0; i < bigEndian.Length; i++)
                le[i] = bigEndian[bigEndian.Length - 1 - i];
            return new BigInteger(le);
        }

        static byte[] ToBigEndianFixed(BigInteger value, int length)
        {
            byte[] le = value.ToByteArray(); // little-endian, may include a trailing 0x00 sign byte
            byte[] result = new byte[length];
            int copy = Math.Min(le.Length, length);
            for (int i = 0; i < copy; i++)
            {
                // skip a pure sign byte that would overflow 'length'
                if (i >= length) break;
                result[length - 1 - i] = le[i];
            }
            return result;
        }
    }
}
