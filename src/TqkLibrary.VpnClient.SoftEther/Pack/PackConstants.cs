namespace TqkLibrary.VpnClient.SoftEther
{
    /// <summary>
    /// Wire limits for the SoftEther PACK serialization, re-implemented from the protocol spec (the 64-bit build
    /// constants, which are the superset accepted by modern servers). These bound decode of untrusted input so a
    /// malformed/huge length prefix cannot drive an unbounded allocation.
    /// </summary>
    public static class PackConstants
    {
        /// <summary>Maximum number of characters in an ELEMENT name (excluding the wire length-prefix quirk).</summary>
        public const int MaxElementNameLength = 63;

        /// <summary>Maximum number of ELEMENTs in a single PACK.</summary>
        public const int MaxElementCount = 262144;

        /// <summary>Maximum number of VALUEs in a single ELEMENT.</summary>
        public const int MaxValueCount = 262144;

        /// <summary>Maximum byte size of a single VALUE payload (data/string).</summary>
        public const int MaxValueSize = 384 * 1024 * 1024;
    }
}
