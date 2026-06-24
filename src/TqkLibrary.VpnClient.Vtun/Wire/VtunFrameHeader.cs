using TqkLibrary.VpnClient.Vtun.Wire.Enums;

namespace TqkLibrary.VpnClient.Vtun.Wire
{
    /// <summary>The decoded meaning of a 2-byte vtun frame header word: its <see cref="Type"/> (data or a control frame)
    /// and, for a data frame, the <see cref="Length"/> of the payload that follows.</summary>
    public readonly struct VtunFrameHeader
    {
        /// <summary>Creates a header value.</summary>
        public VtunFrameHeader(VtunFrameType type, int length)
        {
            Type = type;
            Length = length;
        }

        /// <summary>The frame kind (data / echo-req / echo-rep / conn-close / bad).</summary>
        public VtunFrameType Type { get; }

        /// <summary>The payload byte count for a <see cref="VtunFrameType.Data"/> frame (0 for control frames).</summary>
        public int Length { get; }
    }
}
