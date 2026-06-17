using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;

namespace TqkLibrary.VpnClient.Pptp.Models
{
    /// <summary>
    /// Echo-Request (RFC 2637 §2.5) — control-connection keep-alive. Body: Identifier(4). The peer must answer
    /// with an <see cref="EchoReply"/> echoing the same <see cref="Identifier"/>.
    /// </summary>
    public sealed class EchoRequest : IPptpControlMessage
    {
        /// <inheritdoc/>
        public PptpControlMessageType ControlMessageType => PptpControlMessageType.EchoRequest;

        /// <summary>Opaque identifier the peer echoes back in its <see cref="EchoReply"/>.</summary>
        public uint Identifier { get; set; }
    }
}
