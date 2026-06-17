using System;
using System.Collections.Generic;
using System.Net;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// Builds and reads the DHCPv6 option field (RFC 8415 §21): a sequence of TLV options whose 4-byte header is
    /// <c>(option-code: uint16, option-len: uint16)</c> followed by <c>option-len</c> bytes of value — all big-endian.
    /// Only the codes the L2.6 stateful client needs are modeled: Client/Server Identifier (DUID), IA_NA + the nested
    /// IA Address, Option Request, Elapsed Time, Status Code, and DNS Recursive Name Servers. Mirrors the static,
    /// allocation-light codec style of <see cref="DhcpV4Options"/> / <see cref="Icmpv6Ndisc"/> — no instance state.
    /// </summary>
    public static class Dhcpv6Options
    {
        /// <summary>Option 1 — Client Identifier (the client's DUID), RFC 8415 §21.2.</summary>
        public const ushort CodeClientId = 1;

        /// <summary>Option 2 — Server Identifier (the server's DUID), RFC 8415 §21.3.</summary>
        public const ushort CodeServerId = 2;

        /// <summary>Option 3 — Identity Association for Non-temporary Addresses (IA_NA), RFC 8415 §21.4.</summary>
        public const ushort CodeIaNa = 3;

        /// <summary>Option 5 — IA Address (nested inside an IA_NA), RFC 8415 §21.6.</summary>
        public const ushort CodeIaAddress = 5;

        /// <summary>Option 6 — Option Request (the options a client asks the server to send), RFC 8415 §21.7.</summary>
        public const ushort CodeOptionRequest = 6;

        /// <summary>Option 8 — Elapsed Time (hundredths of a second since the exchange began), RFC 8415 §21.9.</summary>
        public const ushort CodeElapsedTime = 8;

        /// <summary>Option 13 — Status Code (success/no-addresses/…), RFC 8415 §21.13.</summary>
        public const ushort CodeStatusCode = 13;

        /// <summary>Option 23 — DNS Recursive Name Servers, RFC 3646.</summary>
        public const ushort CodeDnsServers = 23;

        /// <summary>Status code value Success (0), RFC 8415 §21.13.</summary>
        public const ushort StatusSuccess = 0;

        /// <summary>Status code value NoAddrsAvail (2) — the server has no addresses for this IA, RFC 8415 §21.13.</summary>
        public const ushort StatusNoAddrsAvail = 2;

        /// <summary>DUID type 3 — DUID based on Link-layer address (DUID-LL), RFC 8415 §11.4.</summary>
        public const ushort DuidTypeLinkLayer = 3;

        /// <summary>Hardware type 1 — Ethernet (RFC 826) used inside a DUID-LL.</summary>
        public const ushort HardwareTypeEthernet = 1;

        /// <summary>Writes one TLV option header + value (big-endian) and returns the next offset.</summary>
        public static int WriteOption(byte[] buffer, int offset, ushort code, ReadOnlySpan<byte> value)
        {
            WriteUInt16(buffer, offset, code);
            WriteUInt16(buffer, offset + 2, (ushort)value.Length);
            value.CopyTo(buffer.AsSpan(offset + 4, value.Length));
            return offset + 4 + value.Length;
        }

        /// <summary>
        /// Builds a DUID-LL (RFC 8415 §11.4): <c>type(2)=3 | hardware-type(2)=1 | link-layer-address</c>. Stable across
        /// reboots for a given MAC, and the value the server echoes back as Client Identifier.
        /// </summary>
        public static byte[] BuildDuidLinkLayer(MacAddress mac)
        {
            byte[] duid = new byte[2 + 2 + MacAddress.Size];
            WriteUInt16(duid, 0, DuidTypeLinkLayer);
            WriteUInt16(duid, 2, HardwareTypeEthernet);
            mac.CopyTo(duid.AsSpan(4, MacAddress.Size));
            return duid;
        }

        /// <summary>
        /// Builds an IA_NA option value (RFC 8415 §21.4): <c>IAID(4) | T1(4) | T2(4)</c> followed by the encapsulated
        /// options (here a single IA Address). A client SOLICIT/REQUEST leaves T1/T2 zero so the server chooses them.
        /// </summary>
        public static byte[] BuildIaNa(uint iaid, uint t1, uint t2, ReadOnlySpan<byte> encapsulatedOptions)
        {
            byte[] value = new byte[12 + encapsulatedOptions.Length];
            WriteUInt32(value, 0, iaid);
            WriteUInt32(value, 4, t1);
            WriteUInt32(value, 8, t2);
            encapsulatedOptions.CopyTo(value.AsSpan(12));
            return value;
        }

        /// <summary>
        /// Builds an IA Address option value (RFC 8415 §21.6): <c>address(16) | preferred-lifetime(4) |
        /// valid-lifetime(4)</c> followed by any encapsulated options (none here). This is the option <i>value</i>; to
        /// nest it inside an IA_NA use <see cref="BuildIaAddressOption"/>, which TLV-wraps it with code 5.
        /// </summary>
        public static byte[] BuildIaAddress(IPAddress address, uint preferredLifetime, uint validLifetime)
        {
            byte[] value = new byte[16 + 4 + 4];
            address.GetAddressBytes().CopyTo(value, 0);
            WriteUInt32(value, 16, preferredLifetime);
            WriteUInt32(value, 20, validLifetime);
            return value;
        }

        /// <summary>
        /// Builds a complete IA Address option (the 4-byte TLV header with code <see cref="CodeIaAddress"/> + the value
        /// from <see cref="BuildIaAddress"/>), ready to be passed as the encapsulated options of an IA_NA.
        /// </summary>
        public static byte[] BuildIaAddressOption(IPAddress address, uint preferredLifetime, uint validLifetime)
        {
            byte[] value = BuildIaAddress(address, preferredLifetime, validLifetime);
            byte[] option = new byte[4 + value.Length];
            WriteOption(option, 0, CodeIaAddress, value);
            return option;
        }

        /// <summary>Builds an Option Request value: a sequence of big-endian option codes the client wants back.</summary>
        public static byte[] BuildOptionRequest(params ushort[] codes)
        {
            byte[] value = new byte[codes.Length * 2];
            for (int i = 0; i < codes.Length; i++)
                WriteUInt16(value, i * 2, codes[i]);
            return value;
        }

        /// <summary>
        /// Finds option <paramref name="code"/> in <paramref name="options"/> (a flat run of TLV options), returning its
        /// value slice. A truncated/malformed option ends the scan.
        /// </summary>
        public static bool TryGetOption(ReadOnlySpan<byte> options, ushort code, out ReadOnlySpan<byte> value)
        {
            value = default;
            int pos = 0;
            while (pos + 4 <= options.Length)
            {
                ushort c = ReadUInt16(options, pos);
                int len = ReadUInt16(options, pos + 2);
                if (pos + 4 + len > options.Length)
                    return false;   // truncated value
                if (c == code)
                {
                    value = options.Slice(pos + 4, len);
                    return true;
                }
                pos += 4 + len;
            }
            return false;
        }

        /// <summary>
        /// Reads the first IA Address (RFC 8415 §21.6) carried inside the IA_NA option (option 3), or <c>null</c> if the
        /// IA_NA is absent or carries no usable address. Also surfaces an embedded Status Code: a non-success status
        /// inside the IA_NA (e.g. NoAddrsAvail) yields <c>null</c>.
        /// </summary>
        public static IPAddress? ReadAssignedAddress(ReadOnlySpan<byte> options, out uint preferredLifetime, out uint validLifetime)
        {
            preferredLifetime = 0;
            validLifetime = 0;
            if (!TryGetOption(options, CodeIaNa, out ReadOnlySpan<byte> iaNa) || iaNa.Length < 12)
                return null;

            ReadOnlySpan<byte> encapsulated = iaNa.Slice(12);   // options after IAID/T1/T2
            // A NoAddrsAvail (or other non-success) status inside the IA means the server assigned nothing.
            if (TryGetOption(encapsulated, CodeStatusCode, out ReadOnlySpan<byte> iaStatus) && iaStatus.Length >= 2
                && ReadUInt16(iaStatus, 0) != StatusSuccess)
                return null;

            if (!TryGetOption(encapsulated, CodeIaAddress, out ReadOnlySpan<byte> iaAddr) || iaAddr.Length < 24)
                return null;
            preferredLifetime = ReadUInt32(iaAddr, 16);
            validLifetime = ReadUInt32(iaAddr, 20);
            return new IPAddress(iaAddr.Slice(0, 16).ToArray());
        }

        /// <summary>Reads the top-level Status Code (option 13), defaulting to <see cref="StatusSuccess"/> if absent.</summary>
        public static ushort ReadStatusCode(ReadOnlySpan<byte> options)
            => TryGetOption(options, CodeStatusCode, out ReadOnlySpan<byte> value) && value.Length >= 2
                ? ReadUInt16(value, 0)
                : StatusSuccess;

        /// <summary>Reads the DNS Recursive Name Servers option (23, a list of 16-byte IPv6 addresses, RFC 3646).</summary>
        public static IReadOnlyList<IPAddress> ReadDnsServers(ReadOnlySpan<byte> options)
        {
            var list = new List<IPAddress>();
            if (TryGetOption(options, CodeDnsServers, out ReadOnlySpan<byte> value) && value.Length % 16 == 0)
            {
                for (int i = 0; i + 16 <= value.Length; i += 16)
                    list.Add(new IPAddress(value.Slice(i, 16).ToArray()));
            }
            return list;
        }

        // ---- Internals ----

        static ushort ReadUInt16(ReadOnlySpan<byte> b, int offset) => (ushort)((b[offset] << 8) | b[offset + 1]);

        static uint ReadUInt32(ReadOnlySpan<byte> b, int offset)
            => ((uint)b[offset] << 24) | ((uint)b[offset + 1] << 16) | ((uint)b[offset + 2] << 8) | b[offset + 3];

        static void WriteUInt16(byte[] b, int offset, ushort value)
        {
            b[offset] = (byte)(value >> 8);
            b[offset + 1] = (byte)value;
        }

        static void WriteUInt32(byte[] b, int offset, uint value)
        {
            b[offset] = (byte)(value >> 24);
            b[offset + 1] = (byte)(value >> 16);
            b[offset + 2] = (byte)(value >> 8);
            b[offset + 3] = (byte)value;
        }
    }
}
