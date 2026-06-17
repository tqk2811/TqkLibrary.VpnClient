using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;

namespace TqkLibrary.VpnClient.Pptp.Models
{
    /// <summary>
    /// Outgoing-Call-Reply (RFC 2637 §2.8) — the PAC's answer to an <see cref="OutgoingCallRequest"/>. Body:
    /// CallID(2), PeerCallID(2), ResultCode(1), ErrorCode(1), CauseCode(2), ConnectSpeed(4),
    /// PacketRecvWindowSize(2), PacketProcessingDelay(2), PhysicalChannelID(4). The call is up only when
    /// <see cref="ResultCode"/> == <see cref="PptpResultCode.Successful"/>; <see cref="PeerCallId"/> is the Call ID
    /// to put in the GRE header of packets sent to the peer.
    /// </summary>
    public sealed class OutgoingCallReply : IPptpControlMessage
    {
        /// <inheritdoc/>
        public PptpControlMessageType ControlMessageType => PptpControlMessageType.OutgoingCallReply;

        /// <summary>Call ID assigned by the answering peer (the PAC).</summary>
        public ushort CallId { get; set; }

        /// <summary>The caller's Call ID echoed back (the value the GRE peer Call ID field carries).</summary>
        public ushort PeerCallId { get; set; }

        /// <summary>Result of the call request (1 = connected).</summary>
        public PptpResultCode ResultCode { get; set; } = PptpResultCode.Successful;

        /// <summary>Error code (valid on a general error result).</summary>
        public byte ErrorCode { get; set; }

        /// <summary>Cause code — additional disconnect/failure reason.</summary>
        public ushort CauseCode { get; set; }

        /// <summary>Actual connect speed (bits/s).</summary>
        public uint ConnectSpeed { get; set; }

        /// <summary>Receive window size negotiated by the answering peer.</summary>
        public ushort PacketRecvWindowSize { get; set; }

        /// <summary>Packet processing delay (units of 1/10 second).</summary>
        public ushort PacketProcessingDelay { get; set; }

        /// <summary>Physical channel ID the call was placed on.</summary>
        public uint PhysicalChannelId { get; set; }
    }
}
