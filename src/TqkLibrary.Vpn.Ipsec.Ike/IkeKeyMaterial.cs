using TqkLibrary.Vpn.Crypto;
using TqkLibrary.Vpn.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.Vpn.Ipsec.Ike
{
    /// <summary>
    /// The seven IKEv2 keys derived in IKE_SA_INIT (RFC 7296 §2.14):
    /// <c>SKEYSEED = prf(Ni|Nr, g^ir)</c> then
    /// <c>{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr} = prf+(SKEYSEED, Ni|Nr|SPIi|SPIr)</c>.
    /// </summary>
    public sealed class IkeKeyMaterial
    {
        IkeKeyMaterial(byte[] skeySeed, byte[] skD, byte[] skAi, byte[] skAr, byte[] skEi, byte[] skEr, byte[] skPi, byte[] skPr)
        {
            SkeySeed = skeySeed;
            SkD = skD; SkAi = skAi; SkAr = skAr; SkEi = skEi; SkEr = skEr; SkPi = skPi; SkPr = skPr;
        }

        /// <summary>The root key SKEYSEED.</summary>
        public byte[] SkeySeed { get; }

        /// <summary>SK_d — used to derive CHILD_SA keying material.</summary>
        public byte[] SkD { get; }

        /// <summary>SK_ai / SK_ar — integrity keys for IKE messages (initiator / responder).</summary>
        public byte[] SkAi { get; }
        /// <summary>SK_ar — responder integrity key.</summary>
        public byte[] SkAr { get; }

        /// <summary>SK_ei / SK_er — encryption keys for IKE messages (initiator / responder).</summary>
        public byte[] SkEi { get; }
        /// <summary>SK_er — responder encryption key.</summary>
        public byte[] SkEr { get; }

        /// <summary>SK_pi / SK_pr — keys that authenticate the AUTH payload (initiator / responder).</summary>
        public byte[] SkPi { get; }
        /// <summary>SK_pr — responder AUTH key.</summary>
        public byte[] SkPr { get; }

        /// <summary>
        /// Derives the key set. <paramref name="encryptionKeyLength"/>/<paramref name="integrityKeyLength"/> are the
        /// negotiated IKE cipher/MAC key sizes; <paramref name="prfKeyLength"/> is the PRF's preferred key size.
        /// </summary>
        public static IkeKeyMaterial Derive(
            IPrf prf,
            byte[] nonceInitiator,
            byte[] nonceResponder,
            byte[] sharedSecret,
            byte[] spiInitiator,
            byte[] spiResponder,
            int encryptionKeyLength,
            int integrityKeyLength,
            int prfKeyLength)
        {
            byte[] noncesKey = Concat(nonceInitiator, nonceResponder);
            byte[] skeyseed = new byte[prf.OutputSizeInBytes];
            prf.Compute(noncesKey, sharedSecret, skeyseed);

            byte[] seed = Concat(nonceInitiator, nonceResponder, spiInitiator, spiResponder);
            int total = prfKeyLength + integrityKeyLength * 2 + encryptionKeyLength * 2 + prfKeyLength * 2;
            byte[] keys = PrfPlus.Expand(prf, skeyseed, seed, total);

            int o = 0;
            byte[] skD = Slice(keys, ref o, prfKeyLength);
            byte[] skAi = Slice(keys, ref o, integrityKeyLength);
            byte[] skAr = Slice(keys, ref o, integrityKeyLength);
            byte[] skEi = Slice(keys, ref o, encryptionKeyLength);
            byte[] skEr = Slice(keys, ref o, encryptionKeyLength);
            byte[] skPi = Slice(keys, ref o, prfKeyLength);
            byte[] skPr = Slice(keys, ref o, prfKeyLength);
            return new IkeKeyMaterial(skeyseed, skD, skAi, skAr, skEi, skEr, skPi, skPr);
        }

        /// <summary>Derives with the project's default IKE suite: AES-CBC-256, HMAC-SHA-256-128, PRF-HMAC-SHA-256.</summary>
        public static IkeKeyMaterial DeriveDefault(
            byte[] nonceInitiator, byte[] nonceResponder, byte[] sharedSecret, byte[] spiInitiator, byte[] spiResponder)
            => Derive(HmacPrf.Sha256(), nonceInitiator, nonceResponder, sharedSecret, spiInitiator, spiResponder,
                encryptionKeyLength: 32, integrityKeyLength: 32, prfKeyLength: 32);

        static byte[] Slice(byte[] source, ref int offset, int length)
        {
            byte[] result = new byte[length];
            Buffer.BlockCopy(source, offset, result, 0, length);
            offset += length;
            return result;
        }

        static byte[] Concat(params byte[][] parts)
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
