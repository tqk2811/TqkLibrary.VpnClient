namespace TqkLibrary.VpnClient.Ipsec.IpComp.Enums
{
    /// <summary>
    /// IPComp Compression Parameter Index (CPI) well-known values (RFC 3173 §4.1): a CPI in 1..63 names a well-known
    /// compression transform — the IANA "IPCOMP Transform Identifiers" registry (referenced by RFC 2407, the IPsec DOI).
    /// For such a transform the on-wire CPI equals its transform id. This client implements <see cref="Deflate"/> only
    /// (RFC 2394 = raw DEFLATE, RFC 1951); the other members are listed for completeness and are rejected on receive.
    /// </summary>
    public enum IpCompTransform : ushort
    {
        /// <summary>Reserved (RFC 3173 §4.1 / IANA transform id 0).</summary>
        Reserved = 0,

        /// <summary>Vendor-specific transform selected by an OUI (IANA transform id 1) — not implemented.</summary>
        Oui = 1,

        /// <summary>DEFLATE (raw DEFLATE RFC 1951, no zlib/gzip wrapper) — RFC 2394, IANA transform id 2. The one implemented here.</summary>
        Deflate = 2,

        /// <summary>LZS stateless compression — RFC 2395, IANA transform id 3 — not implemented.</summary>
        Lzs = 3,

        /// <summary>LZJH (ITU-T V.44) — RFC 3051, IANA transform id 4 — not implemented.</summary>
        LzjhV44 = 4,
    }
}
