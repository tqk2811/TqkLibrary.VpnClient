namespace TqkLibrary.VpnClient.Drivers.Ayiya.Enums
{
    /// <summary>
    /// AYIYA hash method (low nibble of header byte 1, draft-massar-v6ops-ayiya-02). Selects the digest used both for the
    /// signature length (<c>siglen*4</c> = digest size) and for the signature computation over the whole datagram.
    /// </summary>
    public enum AyiyaHashMethod : byte
    {
        /// <summary>No hash / no signature (not valid with shared-secret authentication).</summary>
        None = 0,

        /// <summary>MD5 (16-byte digest → siglen 4).</summary>
        Md5 = 1,

        /// <summary>SHA-1 (20-byte digest → siglen 5). The value aiccu / SixXS deployments use.</summary>
        Sha1 = 2,
    }
}
