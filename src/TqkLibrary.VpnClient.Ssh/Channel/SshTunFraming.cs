using TqkLibrary.VpnClient.Ssh.Channel.Enums;

namespace TqkLibrary.VpnClient.Ssh.Channel
{
    /// <summary>
    /// Encapsulates / decapsulates a layer-3 IP packet for a <c>tun@openssh.com</c> channel (OpenSSH PROTOCOL §2.3). The
    /// channel-data "string" carries:
    /// <code>uint32 packet_length || uint32 address_family || byte[packet_length - 4] ip_packet</code>
    /// where <c>packet_length</c> counts the 4-byte address-family field <b>plus</b> the IP payload (i.e.
    /// <c>4 + ip_packet.Length</c>), and <c>address_family</c> is <see cref="SshTunAddressFamily"/> (2 = IPv4, 24 = IPv6),
    /// chosen from the IP version nibble. A bare IP packet (no link header) sits inside. This is a pure codec.
    /// </summary>
    public static class SshTunFraming
    {
        /// <summary>The fixed framing overhead: the 4-byte inner length field + the 4-byte address-family field.</summary>
        public const int Overhead = 8;

        /// <summary>
        /// Wraps a bare IP packet into the tun@openssh.com channel-data payload. The address family is taken from the IP
        /// version nibble (4 → IPv4, 6 → IPv6); anything else defaults to IPv4.
        /// </summary>
        public static byte[] Encapsulate(ReadOnlySpan<byte> ipPacket)
        {
            SshTunAddressFamily af = (ipPacket.Length > 0 && (ipPacket[0] >> 4) == 6) ? SshTunAddressFamily.Inet6 : SshTunAddressFamily.Inet;
            uint innerLength = (uint)(4 + ipPacket.Length); // address-family field + the IP packet

            byte[] data = new byte[8 + ipPacket.Length];
            WriteUInt32(data, 0, innerLength);
            WriteUInt32(data, 4, (uint)af);
            ipPacket.CopyTo(data.AsSpan(8));
            return data;
        }

        /// <summary>
        /// Extracts the bare IP packet from a tun@openssh.com channel-data payload. Returns false (with an empty result)
        /// when the framing is malformed (too short, or the inner length disagrees with the available bytes).
        /// </summary>
        public static bool TryDecapsulate(ReadOnlySpan<byte> channelData, out ReadOnlySpan<byte> ipPacket, out SshTunAddressFamily addressFamily)
        {
            ipPacket = default;
            addressFamily = SshTunAddressFamily.Inet;
            if (channelData.Length < 8) return false;

            uint innerLength = ReadUInt32(channelData, 0);
            addressFamily = (SshTunAddressFamily)ReadUInt32(channelData, 4);
            if (innerLength < 4) return false;

            int ipLen = (int)innerLength - 4;
            if (8 + ipLen > channelData.Length) return false; // the inner length overruns the buffer
            ipPacket = channelData.Slice(8, ipLen);
            return true;
        }

        static void WriteUInt32(byte[] buffer, int offset, uint value)
        {
            buffer[offset] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)value;
        }

        static uint ReadUInt32(ReadOnlySpan<byte> buffer, int offset)
            => (uint)((buffer[offset] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3]);
    }
}
