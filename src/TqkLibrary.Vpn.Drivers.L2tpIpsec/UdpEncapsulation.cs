namespace TqkLibrary.Vpn.Drivers.L2tpIpsec
{
    /// <summary>
    /// Builds/parses the inner UDP datagram that ESP transport mode protects for L2TP (source/dest port 1701).
    /// The checksum is sent as zero (legal for IPv4 UDP) because, behind NAT, the real addresses needed for the
    /// UDP pseudo-header are unknown to the client — so verification is simply skipped by the peer.
    /// </summary>
    public static class UdpEncapsulation
    {
        /// <summary>The L2TP UDP port used on both ends.</summary>
        public const ushort L2tpPort = 1701;

        const int HeaderSize = 8;

        /// <summary>Wraps <paramref name="payload"/> in a UDP header with checksum 0.</summary>
        public static byte[] Build(ushort sourcePort, ushort destinationPort, ReadOnlySpan<byte> payload)
        {
            int length = HeaderSize + payload.Length;
            byte[] datagram = new byte[length];
            datagram[0] = (byte)(sourcePort >> 8); datagram[1] = (byte)sourcePort;
            datagram[2] = (byte)(destinationPort >> 8); datagram[3] = (byte)destinationPort;
            datagram[4] = (byte)(length >> 8); datagram[5] = (byte)length;
            datagram[6] = 0; datagram[7] = 0; // checksum: 0 = not computed
            payload.CopyTo(datagram.AsSpan(HeaderSize));
            return datagram;
        }

        /// <summary>Extracts ports and payload from a UDP datagram.</summary>
        public static bool TryParse(ReadOnlySpan<byte> datagram, out ushort sourcePort, out ushort destinationPort, out byte[] payload)
        {
            sourcePort = 0; destinationPort = 0; payload = Array.Empty<byte>();
            if (datagram.Length < HeaderSize) return false;

            sourcePort = (ushort)((datagram[0] << 8) | datagram[1]);
            destinationPort = (ushort)((datagram[2] << 8) | datagram[3]);
            int length = (datagram[4] << 8) | datagram[5];
            if (length < HeaderSize || length > datagram.Length) length = datagram.Length;
            payload = datagram.Slice(HeaderSize, length - HeaderSize).ToArray();
            return true;
        }
    }
}
