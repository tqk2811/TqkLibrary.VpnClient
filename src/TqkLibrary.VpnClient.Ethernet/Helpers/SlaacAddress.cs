using System;
using System.Net;

namespace TqkLibrary.VpnClient.Ethernet.Helpers
{
    /// <summary>
    /// Forms a global IPv6 address from an advertised prefix and an interface identifier (Stateless Address
    /// Autoconfiguration, RFC 4862 §5.5.3 / RFC 4291 §2.5.1). Two interface-identifier policies are offered: the classic
    /// <see cref="ModifiedEui64"/> derived from the host MAC (RFC 4291 Appendix A), and a stable opaque identifier
    /// (RFC 7217) seeded from the prefix + MAC so it is constant per (prefix, interface) yet not the bare MAC. Static,
    /// allocation-light, no instance state — like <see cref="Icmpv6Ndisc"/> / <see cref="DhcpV4Packet"/>.
    /// </summary>
    public static class SlaacAddress
    {
        const int InterfaceIdentifierBytes = 8;   // the low 64 bits of an IPv6 address

        /// <summary>
        /// Derives the Modified EUI-64 interface identifier from a 48-bit MAC (RFC 4291 Appendix A): insert
        /// <c>FF:FE</c> in the middle (<c>aabbcc</c>‖<c>FFFE</c>‖<c>ddeeff</c>) and flip the Universal/Local bit (bit 1
        /// of the first octet). Eight bytes.
        /// </summary>
        public static byte[] ModifiedEui64(MacAddress mac)
        {
            Span<byte> m = stackalloc byte[MacAddress.Size];
            mac.CopyTo(m);
            byte[] iid = new byte[InterfaceIdentifierBytes];
            iid[0] = (byte)(m[0] ^ 0x02);   // flip the U/L bit
            iid[1] = m[1];
            iid[2] = m[2];
            iid[3] = 0xFF;
            iid[4] = 0xFE;
            iid[5] = m[3];
            iid[6] = m[4];
            iid[7] = m[5];
            return iid;
        }

        /// <summary>
        /// Derives a stable, opaque interface identifier (RFC 7217) for the given <paramref name="prefix"/> and
        /// <paramref name="mac"/>: <c>SHA-256(prefix64 ‖ MAC)</c> truncated to 8 bytes. Constant per (prefix, interface)
        /// across reboots but not the raw MAC, so it does not leak the hardware address in the address. The U/L bit is
        /// left as produced by the hash (RFC 7217 §5 treats the identifier as opaque).
        /// </summary>
        public static byte[] StableInterfaceIdentifier(IPAddress prefix, MacAddress mac)
        {
            if (prefix is null)
                throw new ArgumentNullException(nameof(prefix));
            byte[] prefixBytes = prefix.GetAddressBytes();
            byte[] input = new byte[InterfaceIdentifierBytes + MacAddress.Size];
            Array.Copy(prefixBytes, 0, input, 0, InterfaceIdentifierBytes);   // the /64 prefix bytes
            mac.CopyTo(input.AsSpan(InterfaceIdentifierBytes));
            using var sha = System.Security.Cryptography.SHA256.Create();
            byte[] hash = sha.ComputeHash(input);
            byte[] iid = new byte[InterfaceIdentifierBytes];
            Array.Copy(hash, 0, iid, 0, InterfaceIdentifierBytes);
            return iid;
        }

        /// <summary>
        /// Combines a <paramref name="prefix"/> (its high <paramref name="prefixLength"/> bits) with an 8-byte
        /// <paramref name="interfaceIdentifier"/> (the low 64 bits) into a global IPv6 address (RFC 4862 §5.5.3).
        /// SLAAC requires a 64-bit prefix; <paramref name="prefixLength"/> must be 64.
        /// </summary>
        public static IPAddress Combine(IPAddress prefix, byte prefixLength, ReadOnlySpan<byte> interfaceIdentifier)
        {
            if (prefix is null)
                throw new ArgumentNullException(nameof(prefix));
            if (prefixLength != 64)
                throw new ArgumentException("SLAAC forms an address from a 64-bit prefix (RFC 4862 §5.5.3).", nameof(prefixLength));
            if (interfaceIdentifier.Length != InterfaceIdentifierBytes)
                throw new ArgumentException($"The interface identifier is {InterfaceIdentifierBytes} bytes.", nameof(interfaceIdentifier));

            byte[] address = prefix.GetAddressBytes();   // 16 bytes; the low 8 are zero for a /64 prefix
            interfaceIdentifier.CopyTo(address.AsSpan(InterfaceIdentifierBytes));
            return new IPAddress(address);
        }
    }
}
