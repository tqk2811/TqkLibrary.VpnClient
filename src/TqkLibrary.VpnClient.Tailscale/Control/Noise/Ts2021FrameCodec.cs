namespace TqkLibrary.VpnClient.Tailscale.Control.Noise
{
    /// <summary>
    /// Codec for the ts2021 control-channel frames (control/controlbase <c>messages.go</c>). All multi-byte integers are
    /// big-endian. Two header shapes:
    /// <list type="bullet">
    /// <item><b>Initiation</b> (type 1): <c>[version:u16][type:1][length:u16][payload]</c> — a 5-byte header (the only
    /// frame that carries a 2-byte protocol version before the type byte).</item>
    /// <item><b>Response/Error/Record</b> (types 2/3/4): <c>[type:1][length:u16][payload]</c> — a 3-byte header.</item>
    /// </list>
    /// <c>length</c> is the byte count of the payload that follows the header (the Noise message for handshake frames,
    /// the ciphertext for record frames). Pure framing only — the Noise crypto is <see cref="Ts2021NoiseHandshake"/> and
    /// the record AEAD is the channel.
    /// </summary>
    public static class Ts2021FrameCodec
    {
        /// <summary>The header length of an initiation frame (version + type + length).</summary>
        public const int InitiationHeaderLength = 5;

        /// <summary>The header length of every non-initiation frame (type + length).</summary>
        public const int HeaderLength = 3;

        /// <summary>Encodes an initiation frame: <c>[version:u16][type=1][length:u16][noiseMessage]</c>.</summary>
        public static byte[] EncodeInitiation(int protocolVersion, ReadOnlySpan<byte> noiseMessage)
        {
            if (noiseMessage.Length > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(noiseMessage));
            var frame = new byte[InitiationHeaderLength + noiseMessage.Length];
            frame[0] = (byte)(protocolVersion >> 8);
            frame[1] = (byte)protocolVersion;
            frame[2] = (byte)Ts2021FrameType.Initiation;
            frame[3] = (byte)(noiseMessage.Length >> 8);
            frame[4] = (byte)noiseMessage.Length;
            noiseMessage.CopyTo(frame.AsSpan(InitiationHeaderLength));
            return frame;
        }

        /// <summary>Encodes a non-initiation frame (response/error/record): <c>[type][length:u16][payload]</c>.</summary>
        public static byte[] EncodeFrame(Ts2021FrameType type, ReadOnlySpan<byte> payload)
        {
            if (type == Ts2021FrameType.Initiation) throw new ArgumentException("Use EncodeInitiation for an initiation frame.", nameof(type));
            if (payload.Length > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(payload));
            var frame = new byte[HeaderLength + payload.Length];
            frame[0] = (byte)type;
            frame[1] = (byte)(payload.Length >> 8);
            frame[2] = (byte)payload.Length;
            payload.CopyTo(frame.AsSpan(HeaderLength));
            return frame;
        }

        /// <summary>
        /// Decodes the 3-byte header of a non-initiation frame at the start of <paramref name="header"/>, yielding the
        /// frame type and the declared payload length. Returns <c>false</c> if fewer than <see cref="HeaderLength"/>
        /// bytes are available.
        /// </summary>
        public static bool TryDecodeHeader(ReadOnlySpan<byte> header, out Ts2021FrameType type, out int payloadLength)
        {
            type = default;
            payloadLength = 0;
            if (header.Length < HeaderLength) return false;
            type = (Ts2021FrameType)header[0];
            payloadLength = (header[1] << 8) | header[2];
            return true;
        }
    }
}
