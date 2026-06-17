using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;

namespace TqkLibrary.VpnClient.Pptp.Models
{
    /// <summary>
    /// Outgoing-Call-Request (RFC 2637 §2.7) — the PNS asks the PAC to place an outbound call (for a VPN client
    /// this requests the GRE session). Body: CallID(2), CallSerialNumber(2), MinBPS(4), MaxBPS(4), BearerType(4),
    /// FramingType(4), PacketRecvWindowSize(2), PacketProcessingDelay(2), PhoneNumberLength(2), Reserved1(2),
    /// PhoneNumber(64), Subaddress(64).
    /// </summary>
    public sealed class OutgoingCallRequest : IPptpControlMessage
    {
        /// <inheritdoc/>
        public PptpControlMessageType ControlMessageType => PptpControlMessageType.OutgoingCallRequest;

        /// <summary>Call ID assigned by the caller (used as the GRE Call ID for received packets).</summary>
        public ushort CallId { get; set; }

        /// <summary>Identifier used to correlate this call with a returned reply.</summary>
        public ushort CallSerialNumber { get; set; }

        /// <summary>Minimum acceptable line speed (bits/s).</summary>
        public uint MinBps { get; set; }

        /// <summary>Maximum acceptable line speed (bits/s).</summary>
        public uint MaxBps { get; set; }

        /// <summary>Bearer type the call should use (1 = analog, 2 = digital, 3 = either).</summary>
        public uint BearerType { get; set; } = 3;

        /// <summary>Framing type the call should use (1 = async, 2 = sync, 3 = either).</summary>
        public uint FramingType { get; set; } = 3;

        /// <summary>Receive window size — number of GRE data packets the caller can buffer.</summary>
        public ushort PacketRecvWindowSize { get; set; } = 64;

        /// <summary>Packet processing delay (in units of 1/10 second).</summary>
        public ushort PacketProcessingDelay { get; set; }

        /// <summary>Phone number — encoded ASCII, NUL-padded to 64 bytes; usually empty for VPN.</summary>
        public string PhoneNumber { get; set; } = string.Empty;

        /// <summary>Sub-address — encoded ASCII, NUL-padded to 64 bytes; usually empty for VPN.</summary>
        public string Subaddress { get; set; } = string.Empty;
    }
}
