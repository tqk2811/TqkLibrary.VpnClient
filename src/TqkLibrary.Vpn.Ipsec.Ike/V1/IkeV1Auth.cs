using TqkLibrary.Vpn.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.Vpn.Ipsec.Ike.V1
{
    /// <summary>
    /// IKEv1 Main Mode authentication hashes (RFC 2409 §5):
    /// <c>HASH_I = prf(SKEYID, g^xi|g^xr|CKY-I|CKY-R|SAi_b|IDi_b)</c> and the responder's mirror
    /// <c>HASH_R = prf(SKEYID, g^xr|g^xi|CKY-R|CKY-I|SAi_b|IDr_b)</c>, where SAi_b is the MM1 SA payload body.
    /// </summary>
    public static class IkeV1Auth
    {
        /// <summary>Computes HASH_I (the value the initiator sends in MM5).</summary>
        public static byte[] ComputeHashI(
            IPrf prf, byte[] skeyid, byte[] keInitiator, byte[] keResponder,
            byte[] cookieInitiator, byte[] cookieResponder, byte[] saInitiatorBody, byte[] idInitiatorBody)
            => Prf(prf, skeyid, IkeV1KeyMaterial.Concat(
                keInitiator, keResponder, cookieInitiator, cookieResponder, saInitiatorBody, idInitiatorBody));

        /// <summary>Computes HASH_R (the value the responder sends in MM6; the initiator verifies it).</summary>
        public static byte[] ComputeHashR(
            IPrf prf, byte[] skeyid, byte[] keInitiator, byte[] keResponder,
            byte[] cookieInitiator, byte[] cookieResponder, byte[] saInitiatorBody, byte[] idResponderBody)
            => Prf(prf, skeyid, IkeV1KeyMaterial.Concat(
                keResponder, keInitiator, cookieResponder, cookieInitiator, saInitiatorBody, idResponderBody));

        static byte[] Prf(IPrf prf, byte[] key, byte[] data)
        {
            byte[] output = new byte[prf.OutputSizeInBytes];
            prf.Compute(key, data, output);
            return output;
        }
    }
}
