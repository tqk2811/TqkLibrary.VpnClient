namespace TqkLibrary.VpnClient.Drivers.Ayiya.Enums
{
    /// <summary>
    /// AYIYA identity type (low nibble of header byte 0, draft-massar-v6ops-ayiya-02). Describes what the Identity field
    /// carries; it is metadata only — the codec does not interpret the identity bytes beyond signing them.
    /// </summary>
    public enum AyiyaIdType : byte
    {
        /// <summary>Integer identity (arbitrary big-endian integer of 2^idlen bytes).</summary>
        Integer = 1,

        /// <summary>String identity (e.g. a tunnel-broker login / username, 2^idlen bytes).</summary>
        String = 2,

        /// <summary>IPv4-address identity (4 bytes → idlen 2).</summary>
        Ipv4 = 4,

        /// <summary>IPv6-address identity (16 bytes → idlen 4). The usual value for a tunnel-broker client endpoint.</summary>
        Ipv6 = 6,
    }
}
