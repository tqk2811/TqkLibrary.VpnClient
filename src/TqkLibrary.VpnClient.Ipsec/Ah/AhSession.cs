using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Ipsec.Ah.Helpers;
using TqkLibrary.VpnClient.Ipsec.Ah.Models;

namespace TqkLibrary.VpnClient.Ipsec.Ah
{
    /// <summary>
    /// An IPsec Authentication Header security association (RFC 4302): connectionless integrity + data-origin
    /// authentication for IP packets, <b>no confidentiality</b>. <see cref="Protect"/> inserts an AH (transport mode) or
    /// wraps the packet in a new outer IP header + AH (tunnel mode) and computes the ICV over the packet with the
    /// mutable IP-header fields zeroed (RFC 4302 §3.3.3); <see cref="TryVerify"/> recomputes the ICV the same way,
    /// compares it in constant time, applies the sliding anti-replay window, and reconstructs the original packet.
    /// <para>
    /// The integrity algorithm (and therefore the ICV/key sizes) is injected as an <see cref="IIntegrityAlgo"/> — pass
    /// <see cref="HmacIntegrity.HmacSha256_128"/> (16-byte ICV) or <see cref="HmacIntegrity.HmacSha1_96"/> (12-byte ICV).
    /// Re-implemented from RFC 4302 (clean-room).
    /// </para>
    /// </summary>
    public sealed class AhSession
    {
        const byte Ipv4TunnelNextHeader = 4;   // IP-in-IP: a tunnelled IPv4 packet (RFC 4302 §3.1.2)
        const byte Ipv6TunnelNextHeader = 41;  // a tunnelled IPv6 packet
        const int Ipv4HeaderSize = 20;         // IHL=5, no options
        const int Ipv6HeaderSize = 40;         // fixed base header, no extension headers

        readonly uint _spi;
        readonly byte[] _key;
        readonly IIntegrityAlgo _integrity;
        readonly bool _tunnelMode;
        readonly IPAddress? _outerSource;
        readonly IPAddress? _outerDestination;
        readonly AntiReplayWindow _replay = new();
        uint _sequence; // last sequence used outbound; the first packet is 1 (RFC 4302 §3.3.2).

        /// <summary>
        /// Creates a session for SPI <paramref name="spi"/> with integrity key <paramref name="key"/> (whose length must
        /// match <paramref name="integrity"/>). <paramref name="tunnelMode"/> selects tunnel vs transport for
        /// <see cref="TryVerify"/> and requires <paramref name="outerSource"/>/<paramref name="outerDestination"/> for
        /// <see cref="Protect"/> to build the outer IP header (both must share an address family — IPv4 or IPv6).
        /// </summary>
        public AhSession(uint spi, byte[] key, IIntegrityAlgo integrity, bool tunnelMode = false,
            IPAddress? outerSource = null, IPAddress? outerDestination = null)
        {
            _integrity = integrity ?? throw new ArgumentNullException(nameof(integrity));
            if (key is null) throw new ArgumentNullException(nameof(key));
            if (key.Length != integrity.KeySizeInBytes)
                throw new ArgumentException($"AH integrity key must be {integrity.KeySizeInBytes} bytes.", nameof(key));
            if (tunnelMode)
            {
                if (outerSource is null || outerDestination is null)
                    throw new ArgumentException("Tunnel mode requires outer source and destination addresses.", nameof(outerSource));
                if (outerSource.AddressFamily != outerDestination.AddressFamily)
                    throw new ArgumentException("Outer source and destination must share an address family.", nameof(outerDestination));
            }
            _spi = spi;
            _key = key;
            _tunnelMode = tunnelMode;
            _outerSource = outerSource;
            _outerDestination = outerDestination;
        }

        /// <summary>The Security Parameters Index this session authenticates.</summary>
        public uint Spi => _spi;

        /// <summary>The last sequence number assigned outbound (0 before the first packet).</summary>
        public uint OutboundSequence => _sequence;

        /// <summary>
        /// Authenticates <paramref name="ipPacket"/> and returns the AH-protected IP packet, assigning the next
        /// sequence number. In transport mode AH is inserted after the IP header (which becomes Protocol 51); in tunnel
        /// mode the whole packet becomes the payload of a fresh outer IP header + AH. The ICV covers the packet with the
        /// mutable IP-header fields zeroed (RFC 4302 §3.3.3). Throws if the outbound sequence would exceed 2³² (RFC 4302
        /// §3.3.2 forbids wrapping without a fresh SA).
        /// </summary>
        public byte[] Protect(ReadOnlySpan<byte> ipPacket, bool tunnelMode)
        {
            uint sequence = checked(_sequence + 1);
            byte[] packet = tunnelMode ? ProtectTunnel(ipPacket, sequence) : ProtectTransport(ipPacket, sequence);
            _sequence = sequence;
            return packet;
        }

        /// <summary>
        /// Verifies an AH-protected packet: checks version/Protocol=51/SPI, recomputes the ICV over a mutable-zeroed
        /// copy and compares it in constant time, then applies the anti-replay window. On success returns the
        /// reconstructed original IP packet (transport: AH removed and Protocol restored; tunnel: the inner packet) in
        /// <paramref name="originalIpPacket"/>, the AH Next Header in <paramref name="nextHeader"/>, and advances the
        /// replay window. Returns false (writing nothing) on any failure; the window only advances once the ICV passes.
        /// </summary>
        public bool TryVerify(ReadOnlySpan<byte> ahPacket, out byte[] originalIpPacket, out byte nextHeader)
        {
            originalIpPacket = Array.Empty<byte>();
            nextHeader = 0;
            if (ahPacket.Length < 1) return false;

            byte version = (byte)(ahPacket[0] >> 4);
            int ipHeaderLength;
            int icvLength = _integrity.IcvSizeInBytes;

            if (version == 4)
            {
                ipHeaderLength = (ahPacket[0] & 0x0F) * 4;
                if (ipHeaderLength != Ipv4HeaderSize) return false; // IPv4 options not supported
                if (ahPacket.Length < ipHeaderLength || ahPacket[9] != AhHeader.ProtocolNumber) return false;
            }
            else if (version == 6)
            {
                ipHeaderLength = Ipv6HeaderSize;
                if (ahPacket.Length < ipHeaderLength || ahPacket[6] != AhHeader.ProtocolNumber) return false;
            }
            else return false;

            if (ahPacket.Length < ipHeaderLength + AhHeader.FixedSize + icvLength) return false;

            AhHeader ah = AhHeader.Parse(ahPacket.Slice(ipHeaderLength));
            if (ah.SecurityParametersIndex != _spi) return false;
            if (ah.IcvLength != icvLength) return false; // ICV size negotiated for this SA doesn't match the packet

            uint sequence = ah.SequenceNumber;
            if (!_replay.Check(sequence)) return false;

            int icvOffset = ipHeaderLength + AhHeader.FixedSize;
            byte[] copy = ahPacket.ToArray();
            if (version == 4) AhMutableFields.ZeroMutableIpv4(copy.AsSpan(0, ipHeaderLength));
            else AhMutableFields.ZeroMutableIpv6(copy.AsSpan(0, ipHeaderLength));
            copy.AsSpan(icvOffset, icvLength).Clear(); // ICV field is zero while computing the ICV (RFC 4302 §3.3.3.1)

            Span<byte> expected = stackalloc byte[icvLength];
            _integrity.ComputeIcv(_key, copy, expected);
            if (!CryptoBytes.FixedTimeEquals(expected, ahPacket.Slice(icvOffset, icvLength))) return false;

            originalIpPacket = _tunnelMode
                ? ahPacket.Slice(icvOffset + icvLength).ToArray()
                : ReconstructTransport(ahPacket, ipHeaderLength, icvLength, ah.NextHeader, version);
            nextHeader = ah.NextHeader;
            _replay.Commit(sequence);
            return true;
        }

        byte[] ProtectTransport(ReadOnlySpan<byte> ipPacket, uint sequence)
        {
            if (ipPacket.Length < 1) throw new ArgumentException("IP packet is empty.", nameof(ipPacket));
            byte version = (byte)(ipPacket[0] >> 4);
            int icvLength = _integrity.IcvSizeInBytes;
            int ahLength = AhHeader.FixedSize + icvLength;

            if (version == 4)
            {
                int ihl = (ipPacket[0] & 0x0F) * 4;
                if (ihl != Ipv4HeaderSize)
                    throw new NotSupportedException("AH transport mode supports IPv4 without options (IHL=5) only (RFC 4302 §3.3.3.1.1.2).");
                byte originalProtocol = ipPacket[9];
                ReadOnlySpan<byte> upper = ipPacket.Slice(ihl);

                byte[] packet = new byte[ihl + ahLength + upper.Length];
                ipPacket.Slice(0, ihl).CopyTo(packet);
                packet[9] = AhHeader.ProtocolNumber;                 // Protocol -> AH (51)
                WriteUInt16(packet, 2, (ushort)packet.Length);        // Total Length
                AhHeader.Create(originalProtocol, _spi, sequence, icvLength).WriteFixed(packet.AsSpan(ihl));
                upper.CopyTo(packet.AsSpan(ihl + ahLength));

                packet[10] = 0; packet[11] = 0;                       // recompute a valid Header Checksum for the wire
                WriteUInt16(packet, 10, InternetChecksum.Compute(packet.AsSpan(0, ihl)));

                PlaceIcv(packet, ihl, icvLength, version);
                return packet;
            }
            if (version == 6)
            {
                if (ipPacket.Length < Ipv6HeaderSize)
                    throw new ArgumentException("IPv6 packet shorter than the 40-byte base header.", nameof(ipPacket));
                RequireIpv6Alignment(ahLength);
                byte originalNextHeader = ipPacket[6];
                ReadOnlySpan<byte> upper = ipPacket.Slice(Ipv6HeaderSize);

                byte[] packet = new byte[Ipv6HeaderSize + ahLength + upper.Length];
                ipPacket.Slice(0, Ipv6HeaderSize).CopyTo(packet);
                packet[6] = AhHeader.ProtocolNumber;                  // Next Header -> AH (51)
                WriteUInt16(packet, 4, (ushort)(ahLength + upper.Length)); // Payload Length
                AhHeader.Create(originalNextHeader, _spi, sequence, icvLength).WriteFixed(packet.AsSpan(Ipv6HeaderSize));
                upper.CopyTo(packet.AsSpan(Ipv6HeaderSize + ahLength));

                PlaceIcv(packet, Ipv6HeaderSize, icvLength, version);
                return packet;
            }
            throw new NotSupportedException("AH supports IPv4 and IPv6 only.");
        }

        byte[] ProtectTunnel(ReadOnlySpan<byte> innerPacket, uint sequence)
        {
            if (innerPacket.Length < 1) throw new ArgumentException("Inner IP packet is empty.", nameof(innerPacket));
            if (_outerSource is null || _outerDestination is null)
                throw new InvalidOperationException("Tunnel-mode Protect requires the session to be constructed with outer addresses.");
            byte innerVersion = (byte)(innerPacket[0] >> 4);
            byte ahNextHeader = innerVersion == 6 ? Ipv6TunnelNextHeader : Ipv4TunnelNextHeader;
            int icvLength = _integrity.IcvSizeInBytes;
            int ahLength = AhHeader.FixedSize + icvLength;

            byte[] ahPlusInner = new byte[ahLength + innerPacket.Length];
            AhHeader.Create(ahNextHeader, _spi, sequence, icvLength).WriteFixed(ahPlusInner);
            innerPacket.CopyTo(ahPlusInner.AsSpan(ahLength));

            if (_outerSource!.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] packet = BuildOuterIpv4(_outerSource!, _outerDestination!, ahPlusInner);
                PlaceIcv(packet, Ipv4HeaderSize, icvLength, 4);
                return packet;
            }
            else
            {
                RequireIpv6Alignment(ahLength);
                byte[] packet = BuildOuterIpv6(_outerSource!, _outerDestination!, ahPlusInner);
                PlaceIcv(packet, Ipv6HeaderSize, icvLength, 6);
                return packet;
            }
        }

        // Computes the ICV over a copy with the mutable IP-header fields + the ICV field zeroed, and writes it into the
        // packet's ICV region (RFC 4302 §3.3.3). The ICV region in `packet` is already zero (WriteFixed never touches it).
        void PlaceIcv(byte[] packet, int ipHeaderLength, int icvLength, byte version)
        {
            byte[] copy = (byte[])packet.Clone();
            if (version == 4) AhMutableFields.ZeroMutableIpv4(copy.AsSpan(0, ipHeaderLength));
            else AhMutableFields.ZeroMutableIpv6(copy.AsSpan(0, ipHeaderLength));
            _integrity.ComputeIcv(_key, copy, packet.AsSpan(ipHeaderLength + AhHeader.FixedSize, icvLength));
        }

        static byte[] ReconstructTransport(ReadOnlySpan<byte> ahPacket, int ipHeaderLength, int icvLength, byte originalProtocol, byte version)
        {
            int ahLength = AhHeader.FixedSize + icvLength;
            ReadOnlySpan<byte> upper = ahPacket.Slice(ipHeaderLength + ahLength);
            byte[] original = new byte[ipHeaderLength + upper.Length];
            ahPacket.Slice(0, ipHeaderLength).CopyTo(original);

            if (version == 4)
            {
                original[9] = originalProtocol;                       // restore Protocol
                WriteUInt16(original, 2, (ushort)original.Length);    // Total Length
                original[10] = 0; original[11] = 0;
                WriteUInt16(original, 10, InternetChecksum.Compute(original.AsSpan(0, ipHeaderLength)));
            }
            else
            {
                original[6] = originalProtocol;                       // restore Next Header
                WriteUInt16(original, 4, (ushort)upper.Length);       // Payload Length
            }
            upper.CopyTo(original.AsSpan(ipHeaderLength));
            return original;
        }

        static byte[] BuildOuterIpv4(IPAddress source, IPAddress destination, ReadOnlySpan<byte> payload)
        {
            byte[] packet = new byte[Ipv4HeaderSize + payload.Length];
            packet[0] = 0x45;                                         // Version 4, IHL 5
            WriteUInt16(packet, 2, (ushort)packet.Length);            // Total Length
            packet[6] = 0x40;                                         // Flags: Don't Fragment
            packet[8] = 64;                                           // TTL
            packet[9] = AhHeader.ProtocolNumber;                      // Protocol: AH (51)
            source.GetAddressBytes().CopyTo(packet, 12);
            destination.GetAddressBytes().CopyTo(packet, 16);
            WriteUInt16(packet, 10, InternetChecksum.Compute(packet.AsSpan(0, Ipv4HeaderSize)));
            payload.CopyTo(packet.AsSpan(Ipv4HeaderSize));
            return packet;
        }

        static byte[] BuildOuterIpv6(IPAddress source, IPAddress destination, ReadOnlySpan<byte> payload)
        {
            byte[] packet = new byte[Ipv6HeaderSize + payload.Length];
            packet[0] = 0x60;                                         // Version 6
            WriteUInt16(packet, 4, (ushort)payload.Length);          // Payload Length
            packet[6] = AhHeader.ProtocolNumber;                      // Next Header: AH (51)
            packet[7] = 64;                                           // Hop Limit
            source.GetAddressBytes().CopyTo(packet, 8);
            destination.GetAddressBytes().CopyTo(packet, 24);
            payload.CopyTo(packet.AsSpan(Ipv6HeaderSize));
            return packet;
        }

        // RFC 4302 §2.6/§3.3.3.2.1: for IPv6 the total AH length must be a multiple of 8 bytes. HMAC-SHA1-96 (24-byte
        // AH) satisfies this; HMAC-SHA-256-128 (28-byte AH) would need implicit ICV padding, which is not implemented.
        static void RequireIpv6Alignment(int ahLength)
        {
            if (ahLength % 8 != 0)
                throw new NotSupportedException(
                    $"AH over IPv6 requires the AH length ({ahLength}) to be a multiple of 8 (RFC 4302 §2.6); " +
                    "ICV sizes needing implicit padding (e.g. HMAC-SHA-256-128) are not implemented — use HMAC-SHA1-96.");
        }

        static void WriteUInt16(byte[] buffer, int offset, ushort value)
        {
            buffer[offset] = (byte)(value >> 8);
            buffer[offset + 1] = (byte)value;
        }
    }
}
