using System.Buffers.Binary;
using TqkLibrary.VpnClient.Vtun.Wire.Enums;

namespace TqkLibrary.VpnClient.Vtun.Wire
{
    /// <summary>
    /// Codec for the vtun data-link framing (vtun's <c>tcp_proto.c</c> / <c>udp_proto.c</c>). Each frame is a 2-byte
    /// <b>big-endian</b> header word followed (for a data frame) by the payload. The header packs the flag bits in the
    /// top nibble and the length in the low 12 bits (<see cref="VtunConstants.FrameSizeMask"/>):
    /// <list type="bullet">
    /// <item>a <b>data</b> frame's header is just its payload length (top nibble zero), then that many payload bytes;</item>
    /// <item>a <b>control</b> frame's header equals a single flag constant (ECHO_REQ/ECHO_REP/CONN_CLOSE), length zero,
    /// no payload.</item>
    /// </list>
    /// With <c>encrypt no</c> + <c>compress no</c> the payload is the bare tunnelled packet (a raw IP packet in tun mode,
    /// a raw Ethernet frame in tap mode) — there is no per-frame crypto/compression header. Pure codec — no I/O.
    /// </summary>
    public static class VtunFrameCodec
    {
        /// <summary>The frame header length in bytes (the big-endian length+flags word).</summary>
        public const int HeaderSize = 2;

        /// <summary>
        /// Encodes a data frame (<paramref name="payload"/> with a 2-byte header) into <paramref name="destination"/>;
        /// returns the total bytes written (<c>2 + payload.Length</c>). <paramref name="destination"/> must be at least
        /// that long. The length must fit <see cref="VtunConstants.FrameSizeMask"/>.
        /// </summary>
        public static int EncodeData(ReadOnlySpan<byte> payload, Span<byte> destination)
        {
            if (payload.Length > VtunConstants.FrameSizeMask)
                throw new ArgumentException($"vtun frame payload exceeds {VtunConstants.FrameSizeMask} bytes.", nameof(payload));
            int total = HeaderSize + payload.Length;
            if (destination.Length < total)
                throw new ArgumentException("Destination too small for the vtun frame.", nameof(destination));

            BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)payload.Length);
            payload.CopyTo(destination.Slice(HeaderSize));
            return total;
        }

        /// <summary>Allocates and returns a complete data frame (header + payload).</summary>
        public static byte[] EncodeData(ReadOnlySpan<byte> payload)
        {
            byte[] frame = new byte[HeaderSize + payload.Length];
            EncodeData(payload, frame);
            return frame;
        }

        /// <summary>
        /// Encodes a zero-payload control frame (its header word is the flag value) into <paramref name="destination"/>
        /// (≥ 2 bytes); returns 2. <paramref name="type"/> must be a control type (not <see cref="VtunFrameType.Data"/>).
        /// </summary>
        public static int EncodeControl(VtunFrameType type, Span<byte> destination)
        {
            ushort word = type switch
            {
                VtunFrameType.EchoRequest => VtunConstants.EchoRequest,
                VtunFrameType.EchoReply => VtunConstants.EchoReply,
                VtunFrameType.ConnClose => VtunConstants.ConnClose,
                VtunFrameType.BadFrame => VtunConstants.BadFrame,
                _ => throw new ArgumentException("Not a control frame type.", nameof(type)),
            };
            if (destination.Length < HeaderSize)
                throw new ArgumentException("Destination too small for the vtun control frame.", nameof(destination));
            BinaryPrimitives.WriteUInt16BigEndian(destination, word);
            return HeaderSize;
        }

        /// <summary>Allocates and returns a 2-byte control frame for <paramref name="type"/>.</summary>
        public static byte[] EncodeControl(VtunFrameType type)
        {
            byte[] frame = new byte[HeaderSize];
            EncodeControl(type, frame);
            return frame;
        }

        /// <summary>
        /// Decodes a 2-byte header word (big-endian) into its <see cref="VtunFrameHeader"/>. If any flag bit is set the
        /// word is a control frame (the length bits are ignored); otherwise it is a data frame whose length is the low 12
        /// bits. A length that exceeds <see cref="VtunConstants.FrameSize"/> + <see cref="VtunConstants.FrameOverhead"/>
        /// decodes to <see cref="VtunFrameType.BadFrame"/> (matching vtun's oversized-frame guard).
        /// </summary>
        public static VtunFrameHeader DecodeHeader(ReadOnlySpan<byte> header)
        {
            if (header.Length < HeaderSize)
                throw new ArgumentException("vtun header needs 2 bytes.", nameof(header));

            ushort word = BinaryPrimitives.ReadUInt16BigEndian(header);
            int length = word & VtunConstants.FrameSizeMask;
            ushort flags = (ushort)(word & ~VtunConstants.FrameSizeMask);

            if (flags == 0)
            {
                if (length > VtunConstants.FrameSize + VtunConstants.FrameOverhead)
                    return new VtunFrameHeader(VtunFrameType.BadFrame, 0);
                return new VtunFrameHeader(VtunFrameType.Data, length);
            }

            // A flag is set — control frame. vtun sets exactly one flag per control frame.
            if ((flags & VtunConstants.BadFrame) != 0) return new VtunFrameHeader(VtunFrameType.BadFrame, 0);
            if ((flags & VtunConstants.EchoReply) != 0) return new VtunFrameHeader(VtunFrameType.EchoReply, 0);
            if ((flags & VtunConstants.EchoRequest) != 0) return new VtunFrameHeader(VtunFrameType.EchoRequest, 0);
            if ((flags & VtunConstants.ConnClose) != 0) return new VtunFrameHeader(VtunFrameType.ConnClose, 0);
            return new VtunFrameHeader(VtunFrameType.BadFrame, 0);
        }
    }
}
