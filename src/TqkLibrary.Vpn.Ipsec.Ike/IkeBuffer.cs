namespace TqkLibrary.Vpn.Ipsec.Ike
{
    /// <summary>Internal big-endian write/read helpers for IKEv2 framing over a growable byte list / span.</summary>
    internal static class IkeBuffer
    {
        public static void WriteUInt16(List<byte> output, ushort value)
        {
            output.Add((byte)(value >> 8));
            output.Add((byte)value);
        }

        public static void WriteUInt32(List<byte> output, uint value)
        {
            output.Add((byte)(value >> 24));
            output.Add((byte)(value >> 16));
            output.Add((byte)(value >> 8));
            output.Add((byte)value);
        }

        public static ushort ReadUInt16(ReadOnlySpan<byte> buffer, int offset)
            => (ushort)((buffer[offset] << 8) | buffer[offset + 1]);

        public static uint ReadUInt32(ReadOnlySpan<byte> buffer, int offset)
            => (uint)((buffer[offset] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3]);
    }
}
