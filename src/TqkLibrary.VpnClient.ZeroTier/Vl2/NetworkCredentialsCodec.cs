using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.ZeroTier.Vl2
{
    /// <summary>
    /// Builds the body of a VL1 <c>NETWORK_CREDENTIALS</c> verb (0x0a) — the modern, non-deprecated way to present a
    /// node's certificate of membership (COM) to a peer so it accepts the node's L2 frames. The body is a run of one or
    /// more serialized COMs terminated by a single <c>0x00</c> byte, then four 16-bit big-endian counts each followed by
    /// their (here empty) credential lists: capabilities, tags, revocations, certificates of ownership.
    /// <para>
    /// This client only ever presents the single COM the controller issued it, with all four credential counts zero — the
    /// minimal body a peer needs to clear an <c>ERROR NEED_MEMBERSHIP_CERTIFICATE</c>.
    /// </para>
    /// </summary>
    public sealed class NetworkCredentialsCodec
    {
        /// <summary>
        /// Serialises a NETWORK_CREDENTIALS body carrying the single <paramref name="certificateOfMembership"/> and no
        /// other credentials. The COM bytes are written verbatim (already in <c>CertificateOfMembership::serialize</c>
        /// form, as received from the controller's network config).
        /// </summary>
        public byte[] EncodeMembershipOnly(byte[] certificateOfMembership)
        {
            if (certificateOfMembership is null) throw new System.ArgumentNullException(nameof(certificateOfMembership));
            // COM bytes || 0x00 (end of COM array) || caps(2)=0 || tags(2)=0 || revocations(2)=0 || coo(2)=0
            byte[] body = new byte[certificateOfMembership.Length + 1 + 2 + 2 + 2 + 2];
            int o = 0;
            certificateOfMembership.CopyTo(body, o);
            o += certificateOfMembership.Length;
            body[o++] = 0x00;                                              // null byte terminates the COM array
            BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(o, 2), 0); o += 2;  // capabilities count
            BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(o, 2), 0); o += 2;  // tags count
            BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(o, 2), 0); o += 2;  // revocations count
            BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(o, 2), 0);          // certificates-of-ownership count
            return body;
        }
    }
}
