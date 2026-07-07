using System.Net;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.IpStack;

namespace TqkLibrary.VpnClient.MapT.Tests;

/// <summary>Byte-exact packet builders for the MAP-T double-translation tests (reusing the IpStack codecs).</summary>
static class TestPackets
{
    public static IPAddress V4(string s) => IPAddress.Parse(s);
    public static IPAddress V6(string s) => IPAddress.Parse(s);

    /// <summary>Builds a UDP segment (8-byte header + data) with a valid IPv4/IPv6 pseudo-header checksum.</summary>
    public static byte[] UdpSegment(IPAddress src, IPAddress dst, ushort sport, ushort dport, byte[] data)
    {
        byte[] seg = new byte[8 + data.Length];
        seg[0] = (byte)(sport >> 8); seg[1] = (byte)sport;
        seg[2] = (byte)(dport >> 8); seg[3] = (byte)dport;
        int len = seg.Length;
        seg[4] = (byte)(len >> 8); seg[5] = (byte)len;
        Array.Copy(data, 0, seg, 8, data.Length);
        uint sum = InternetChecksum.PseudoHeaderSum(src, dst, Ipv4.ProtocolUdp, seg.Length);
        sum = InternetChecksum.AddData(sum, seg);
        ushort c = InternetChecksum.Finish(sum);
        if (c == 0) c = 0xFFFF;
        seg[6] = (byte)(c >> 8); seg[7] = (byte)c;
        return seg;
    }

    /// <summary>Builds a minimal TCP segment (20-byte header + data) with a valid pseudo-header checksum.</summary>
    public static byte[] TcpSegment(IPAddress src, IPAddress dst, ushort sport, ushort dport, byte[] data)
    {
        byte[] seg = new byte[20 + data.Length];
        seg[0] = (byte)(sport >> 8); seg[1] = (byte)sport;
        seg[2] = (byte)(dport >> 8); seg[3] = (byte)dport;
        seg[4] = 0x00; seg[5] = 0x00; seg[6] = 0x00; seg[7] = 0x01;   // seq
        seg[12] = 0x50;                                              // data offset 5 (20 bytes)
        seg[13] = 0x18;                                             // PSH | ACK
        seg[14] = 0xFF; seg[15] = 0xFF;                            // window
        Array.Copy(data, 0, seg, 20, data.Length);
        uint sum = InternetChecksum.PseudoHeaderSum(src, dst, Ipv4.ProtocolTcp, seg.Length);
        sum = InternetChecksum.AddData(sum, seg);
        ushort c = InternetChecksum.Finish(sum);
        seg[16] = (byte)(c >> 8); seg[17] = (byte)c;
        return seg;
    }

    /// <summary>Wraps <paramref name="payload"/> in an IPv4 header (DF set) and overwrites the TTL.</summary>
    public static byte[] Ipv4Packet(IPAddress src, IPAddress dst, byte protocol, byte[] payload, ushort id, byte ttl)
    {
        byte[] p = Ipv4.Build(src, dst, protocol, payload, id);
        p[8] = ttl;
        RewriteIpv4Checksum(p);
        return p;
    }

    public static void RewriteIpv4Checksum(byte[] p)
    {
        p[10] = 0; p[11] = 0;
        ushort c = InternetChecksum.Compute(p.AsSpan(0, 20));
        p[10] = (byte)(c >> 8); p[11] = (byte)c;
    }

    public static bool VerifyUdpTcpChecksum(IPAddress src, IPAddress dst, byte protocol, ReadOnlySpan<byte> segment)
    {
        uint sum = InternetChecksum.PseudoHeaderSum(src, dst, protocol, segment.Length);
        sum = InternetChecksum.AddData(sum, segment);
        return InternetChecksum.Finish(sum) == 0;
    }
}
