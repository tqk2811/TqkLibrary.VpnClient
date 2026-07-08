namespace TqkLibrary.VpnClient.Transport.WebSocket
{
    /// <summary>
    /// RFC 6455 §5.2 frame opcodes (the low 4 bits of the first framing byte). Data frames carry the tunnelled
    /// application bytes (<see cref="Binary"/> is used for the byte-stream tunnel); <see cref="Continuation"/> continues a
    /// fragmented data message; the three control opcodes (<see cref="Close"/>/<see cref="Ping"/>/<see cref="Pong"/>, all
    /// with bit <c>0x08</c> set) carry protocol control and MUST have a payload ≤ 125 bytes and FIN = 1 (§5.5).
    /// </summary>
    public enum Rfc6455Opcode : byte
    {
        /// <summary>0x0 — continuation of a fragmented data message (§5.4).</summary>
        Continuation = 0x0,

        /// <summary>0x1 — UTF-8 text data frame (§5.6).</summary>
        Text = 0x1,

        /// <summary>0x2 — binary data frame (§5.6); the opcode the byte-stream tunnel uses.</summary>
        Binary = 0x2,

        /// <summary>0x8 — connection close control frame (§5.5.1).</summary>
        Close = 0x8,

        /// <summary>0x9 — ping control frame (§5.5.2); the peer answers with a <see cref="Pong"/> carrying the same payload.</summary>
        Ping = 0x9,

        /// <summary>0xA — pong control frame (§5.5.3), sent in reply to a <see cref="Ping"/>.</summary>
        Pong = 0xA,
    }
}
