namespace TqkLibrary.VpnClient.Tailscale.Control.Noise
{
    /// <summary>
    /// The ts2021 control-channel frame types (control/controlbase <c>messages.go</c>). The initiation frame is the only
    /// one whose header is 5 bytes (a 2-byte protocol version precedes the type); every other frame uses a 3-byte header
    /// (type + 2-byte big-endian length).
    /// </summary>
    public enum Ts2021FrameType : byte
    {
        /// <summary>Initiator handshake message 1 (<c>msgTypeInitiation</c>); 5-byte header.</summary>
        Initiation = 1,

        /// <summary>Responder handshake message 2 (<c>msgTypeResponse</c>).</summary>
        Response = 2,

        /// <summary>An error frame carrying a cleartext ASCII message (<c>msgTypeError</c>).</summary>
        Error = 3,

        /// <summary>A transport record after the handshake (<c>msgTypeRecord</c>): an encrypted ChaCha20-Poly1305 chunk.</summary>
        Record = 4,
    }
}
