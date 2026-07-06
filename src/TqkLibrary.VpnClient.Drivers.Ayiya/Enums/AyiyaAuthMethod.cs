namespace TqkLibrary.VpnClient.Drivers.Ayiya.Enums
{
    /// <summary>
    /// AYIYA authentication method (high nibble of header byte 2, draft-massar-v6ops-ayiya-02). Selects how the signature
    /// field is filled. This static-mode driver implements only <see cref="SharedSecret"/>.
    /// </summary>
    public enum AyiyaAuthMethod : byte
    {
        /// <summary>No authentication (signature field unused).</summary>
        None = 0,

        /// <summary>Shared-secret authentication: the signature is a keyed hash over the whole datagram (aiccu algorithm).</summary>
        SharedSecret = 1,

        /// <summary>PGP-signature authentication (not implemented here).</summary>
        Pgp = 2,
    }
}
