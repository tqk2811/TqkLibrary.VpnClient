using System.Net;
using System.Net.Sockets;

namespace TqkLibrary.VpnClient.WireGuard.Routing
{
    /// <summary>
    /// A single CIDR network prefix (the unit of a WireGuard peer's <c>AllowedIPs</c>) — a network address plus a
    /// prefix length, for either address family. It is a small immutable value object that parses <c>"10.0.0.0/24"</c>
    /// or <c>"2001:db8::/48"</c> (or a bare host address ⇒ a full-length prefix) and answers <see cref="Contains"/>
    /// for crypto-routing's longest-prefix match. The network address is masked to the prefix on construction so two
    /// prefixes that name the same network compare equal regardless of any host bits in the input.
    /// <para>
    /// This is a pure value type (no I/O, no sockets) so the routing table can be built and tested offline. It holds
    /// the masked network as raw bytes (4 or 16) and the prefix length in bits; <see cref="PrefixLength"/> doubles as
    /// the match specificity for longest-prefix selection.
    /// </para>
    /// </summary>
    public readonly struct IpPrefix : IEquatable<IpPrefix>
    {
        readonly byte[] _network; // masked network address, 4 bytes (IPv4) or 16 bytes (IPv6)

        /// <summary>The address family of this prefix (<see cref="AddressFamily.InterNetwork"/> or <see cref="AddressFamily.InterNetworkV6"/>).</summary>
        public AddressFamily Family { get; }

        /// <summary>The prefix length in bits (0..32 for IPv4, 0..128 for IPv6); also the longest-prefix match specificity.</summary>
        public int PrefixLength { get; }

        IpPrefix(byte[] maskedNetwork, AddressFamily family, int prefixLength)
        {
            _network = maskedNetwork;
            Family = family;
            PrefixLength = prefixLength;
        }

        /// <summary>The number of address bits for this prefix's family (32 for IPv4, 128 for IPv6).</summary>
        public int MaxPrefixLength => Family == AddressFamily.InterNetworkV6 ? 128 : 32;

        /// <summary>
        /// Parses CIDR text (<c>"net/prefix"</c>) or a bare host address (treated as a full-length prefix). Returns
        /// <c>false</c> (no throw) for anything that does not parse, an out-of-range prefix length, or a prefix length
        /// that does not match the address family.
        /// </summary>
        public static bool TryParse(string text, out IpPrefix prefix)
        {
            prefix = default;
            if (string.IsNullOrWhiteSpace(text)) return false;

            string trimmed = text.Trim();
            int slash = trimmed.IndexOf('/');
            string addressPart = slash < 0 ? trimmed : trimmed.Substring(0, slash);
            if (!IPAddress.TryParse(addressPart, out IPAddress? address)) return false;
            if (address.AddressFamily != AddressFamily.InterNetwork && address.AddressFamily != AddressFamily.InterNetworkV6)
                return false;

            byte[] bytes = address.GetAddressBytes();
            int maxBits = bytes.Length * 8;
            int prefixLength;
            if (slash < 0)
            {
                prefixLength = maxBits; // bare host ⇒ /32 or /128
            }
            else
            {
                string lengthPart = trimmed.Substring(slash + 1);
                if (!int.TryParse(lengthPart, out prefixLength)) return false;
                if (prefixLength < 0 || prefixLength > maxBits) return false;
            }

            MaskInPlace(bytes, prefixLength);
            prefix = new IpPrefix(bytes, address.AddressFamily, prefixLength);
            return true;
        }

        /// <summary>
        /// True if <paramref name="address"/> falls inside this prefix: same family and the first
        /// <see cref="PrefixLength"/> bits of the masked address equal this prefix's network. A <c>/0</c> prefix
        /// matches every address of its family (the WireGuard full-tunnel default).
        /// </summary>
        public bool Contains(IPAddress address)
        {
            if (address is null) return false;
            if (address.AddressFamily != Family) return false;
            byte[] candidate = address.GetAddressBytes();
            if (candidate.Length != _network.Length) return false;
            return MatchesBits(candidate, _network, PrefixLength);
        }

        // Compares the first <paramref name="bits"/> bits of two equal-length byte arrays.
        static bool MatchesBits(byte[] a, byte[] b, int bits)
        {
            int fullBytes = bits / 8;
            for (int i = 0; i < fullBytes; i++)
                if (a[i] != b[i]) return false;
            int remaining = bits & 7;
            if (remaining == 0) return true;
            int mask = 0xFF << (8 - remaining) & 0xFF;
            return (a[fullBytes] & mask) == (b[fullBytes] & mask);
        }

        // Zeroes every bit of <paramref name="bytes"/> beyond <paramref name="prefixLength"/> so the network is canonical.
        static void MaskInPlace(byte[] bytes, int prefixLength)
        {
            int fullBytes = prefixLength / 8;
            int remaining = prefixLength & 7;
            int index = fullBytes;
            if (remaining != 0)
            {
                int mask = 0xFF << (8 - remaining) & 0xFF;
                bytes[index] = (byte)(bytes[index] & mask);
                index++;
            }
            for (; index < bytes.Length; index++) bytes[index] = 0;
        }

        /// <inheritdoc/>
        public bool Equals(IpPrefix other)
        {
            if (Family != other.Family || PrefixLength != other.PrefixLength) return false;
            if (_network is null || other._network is null) return ReferenceEquals(_network, other._network);
            if (_network.Length != other._network.Length) return false;
            for (int i = 0; i < _network.Length; i++)
                if (_network[i] != other._network[i]) return false;
            return true;
        }

        /// <inheritdoc/>
        public override bool Equals(object? obj) => obj is IpPrefix other && Equals(other);

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            int hash = (int)Family * 397 ^ PrefixLength;
            if (_network != null)
                foreach (byte b in _network) hash = hash * 31 + b;
            return hash;
        }

        /// <inheritdoc/>
        public override string ToString() => $"{new IPAddress(_network ?? Array.Empty<byte>())}/{PrefixLength}";
    }
}
