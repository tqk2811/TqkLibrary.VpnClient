namespace TqkLibrary.VpnClient.Siit.Enums;

/// <summary>Why a SIIT translation returned <c>null</c> (RFC 7915 "safe drop"). Recorded on <see cref="SiitTranslator.LastDropReason"/>.</summary>
public enum SiitDropReason
{
    /// <summary>No drop — the last translation succeeded.</summary>
    None = 0,

    /// <summary>Packet too short, wrong version nibble, or a length field that does not fit the buffer.</summary>
    Malformed,

    /// <summary>IPv4 TTL ≤ 1 (or IPv6 Hop Limit ≤ 1): decrementing would reach zero (RFC 7915 §4/§5).</summary>
    HopLimitExceeded,

    /// <summary>Upper-layer protocol is not one of ICMP/TCP/UDP.</summary>
    UnsupportedProtocol,

    /// <summary>An IPv6 extension header other than a single Fragment header was present (Hop-by-Hop/Routing/Dest-Options).</summary>
    UnsupportedExtensionHeader,

    /// <summary>Source or destination address could not be mapped by the configured <see cref="Interfaces.IAddressTranslator"/>.</summary>
    AddressNotMapped,

    /// <summary>Source or destination is a multicast address (not translated, RFC 7915).</summary>
    Multicast,

    /// <summary>ICMP message type/code has no defined translation in this engine.</summary>
    UnsupportedIcmp,

    /// <summary>ICMP carried in a fragmented datagram — not translated (checksum spans all fragments).</summary>
    FragmentedIcmp,

    /// <summary>IPv4 UDP with a zero checksum arrived as a fragment: IPv6 requires a checksum but it cannot be computed without the whole datagram (RFC 7915 §4.5).</summary>
    UdpZeroChecksumFragment,
}
