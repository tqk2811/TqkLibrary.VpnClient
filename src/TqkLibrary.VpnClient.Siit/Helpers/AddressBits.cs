namespace TqkLibrary.VpnClient.Siit.Helpers;

/// <summary>
/// MSB-first bit-string operations over byte buffers, used by the RFC 7757 EAM prefix/suffix copy where
/// prefix lengths are not necessarily byte-aligned. Pure/stateless.
/// </summary>
public static class AddressBits
{
    /// <summary>Returns true if the first <paramref name="bitCount"/> bits (MSB-first) of <paramref name="address"/> equal those of <paramref name="prefix"/>.</summary>
    public static bool PrefixMatches(ReadOnlySpan<byte> address, ReadOnlySpan<byte> prefix, int bitCount)
    {
        int fullBytes = bitCount / 8;
        for (int i = 0; i < fullBytes; i++)
            if (address[i] != prefix[i]) return false;

        int remBits = bitCount & 7;
        if (remBits != 0)
        {
            int mask = (0xFF << (8 - remBits)) & 0xFF;
            if ((address[fullBytes] & mask) != (prefix[fullBytes] & mask)) return false;
        }
        return true;
    }

    /// <summary>Reads a single bit (MSB-first) at <paramref name="bitIndex"/>.</summary>
    public static int GetBit(ReadOnlySpan<byte> buffer, int bitIndex)
        => (buffer[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1;

    /// <summary>Writes a single bit (MSB-first) at <paramref name="bitIndex"/>.</summary>
    public static void SetBit(Span<byte> buffer, int bitIndex, int value)
    {
        int mask = 1 << (7 - (bitIndex & 7));
        if (value != 0) buffer[bitIndex >> 3] |= (byte)mask;
        else buffer[bitIndex >> 3] &= (byte)~mask;
    }

    /// <summary>Copies <paramref name="count"/> bits (MSB-first) from <paramref name="src"/>@<paramref name="srcBit"/> into <paramref name="dst"/>@<paramref name="dstBit"/>.</summary>
    public static void CopyBits(Span<byte> dst, int dstBit, ReadOnlySpan<byte> src, int srcBit, int count)
    {
        for (int i = 0; i < count; i++)
            SetBit(dst, dstBit + i, GetBit(src, srcBit + i));
    }
}
