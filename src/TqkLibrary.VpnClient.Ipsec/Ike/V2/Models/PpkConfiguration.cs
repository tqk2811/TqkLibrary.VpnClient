namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Models
{
    /// <summary>
    /// A Post-quantum Preshared Key configured for one IKEv2 peer (RFC 8784): the identifier the initiator advertises
    /// in the PPK_IDENTITY notification (<see cref="PpkId"/>), the secret mixed into the IKE keys (<see cref="Ppk"/>),
    /// and whether its use is <see cref="Mandatory"/>. When mandatory, the client aborts if the responder does not
    /// echo USE_PPK; when optional, it falls back to standard authentication and offers NO_PPK_AUTH.
    /// </summary>
    public sealed record PpkConfiguration
    {
        /// <summary>The bare PPK identifier value (without the leading PPK_ID Type octet). See <see cref="ToWirePpkId"/>.</summary>
        public required byte[] PpkId { get; init; }

        /// <summary>The Post-quantum Preshared Key itself — the secret keyed into <c>prf(PPK, SK_*)</c> (RFC 8784 §3).</summary>
        public required byte[] Ppk { get; init; }

        /// <summary>When true, abort the exchange if the responder does not agree to use a PPK (echo USE_PPK).</summary>
        public bool Mandatory { get; init; }

        /// <summary>
        /// The PPK_ID Type octet that prefixes the identifier on the wire (RFC 8784 §4.1). Defaults to
        /// <c>1</c> = <c>PPK_ID_OPAQUE</c>, the only type the RFC defines.
        /// </summary>
        public byte PpkIdType { get; init; } = 1;

        /// <summary>
        /// The wire-format PPK_ID carried in a PPK_IDENTITY notification (RFC 8784 §4.1): the
        /// <see cref="PpkIdType"/> octet followed by <see cref="PpkId"/>.
        /// </summary>
        public byte[] ToWirePpkId()
        {
            byte[] wire = new byte[PpkId.Length + 1];
            wire[0] = PpkIdType;
            System.Buffer.BlockCopy(PpkId, 0, wire, 1, PpkId.Length);
            return wire;
        }
    }
}
