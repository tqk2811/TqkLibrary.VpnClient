using System.Net;
using System.Net.Sockets;

namespace TqkLibrary.VpnClient.WireGuard.Routing
{
    /// <summary>
    /// Reads the destination address out of a bare IP packet — the minimum a WireGuard data channel needs for
    /// crypto-routing (pick the peer whose <c>AllowedIPs</c> covers the destination). It only inspects the version
    /// nibble and the fixed destination-address field (IPv4 offset 16, IPv6 offset 24); it does not parse options or
    /// extension headers, which are irrelevant to the destination. A separate, deliberately tiny reader (rather than a
    /// dependency on the full IP stack) keeps this protocol project's footprint to <c>Abstractions</c> + <c>Crypto</c>.
    /// </summary>
    public static class IpPacketDestination
    {
        const int Ipv4MinLength = 20;
        const int Ipv4DestinationOffset = 16;
        const int Ipv6Length = 40;
        const int Ipv6DestinationOffset = 24;

        /// <summary>
        /// Extracts the destination <see cref="IPAddress"/> from <paramref name="ipPacket"/>. Returns <c>false</c>
        /// (no throw) for an empty packet, an unknown IP version, or one too short to hold its destination field.
        /// </summary>
        public static bool TryGetDestination(ReadOnlySpan<byte> ipPacket, out IPAddress destination)
        {
            destination = IPAddress.None;
            if (ipPacket.Length < 1) return false;

            int version = ipPacket[0] >> 4;
            switch (version)
            {
                case 4:
                    if (ipPacket.Length < Ipv4MinLength) return false;
                    destination = new IPAddress(ipPacket.Slice(Ipv4DestinationOffset, 4).ToArray());
                    return true;
                case 6:
                    if (ipPacket.Length < Ipv6Length) return false;
                    destination = new IPAddress(ipPacket.Slice(Ipv6DestinationOffset, 16).ToArray());
                    return true;
                default:
                    return false;
            }
        }

        /// <summary>The address family implied by the IP version nibble, or <see cref="AddressFamily.Unknown"/> if neither 4 nor 6.</summary>
        public static AddressFamily FamilyOf(ReadOnlySpan<byte> ipPacket)
        {
            if (ipPacket.Length < 1) return AddressFamily.Unknown;
            return (ipPacket[0] >> 4) switch
            {
                4 => AddressFamily.InterNetwork,
                6 => AddressFamily.InterNetworkV6,
                _ => AddressFamily.Unknown,
            };
        }
    }
}
