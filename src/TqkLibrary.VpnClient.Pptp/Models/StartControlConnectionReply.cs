using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;

namespace TqkLibrary.VpnClient.Pptp.Models
{
    /// <summary>
    /// Start-Control-Connection-Reply (RFC 2637 §2.2) — the answer to a
    /// <see cref="StartControlConnectionRequest"/>. Body: ProtocolVersion(2), ResultCode(1), ErrorCode(1),
    /// FramingCapabilities(4), BearerCapabilities(4), MaximumChannels(2), FirmwareRevision(2),
    /// HostName(64), VendorName(64). The control connection is up only when
    /// <see cref="ResultCode"/> == <see cref="PptpResultCode.Successful"/>.
    /// </summary>
    public sealed class StartControlConnectionReply : IPptpControlMessage
    {
        /// <inheritdoc/>
        public PptpControlMessageType ControlMessageType => PptpControlMessageType.StartControlConnectionReply;

        /// <summary>PPTP protocol version of the responder.</summary>
        public ushort ProtocolVersion { get; set; } = 0x0100;

        /// <summary>Result of the request (1 = successful).</summary>
        public PptpResultCode ResultCode { get; set; } = PptpResultCode.Successful;

        /// <summary>Error code (valid when <see cref="ResultCode"/> indicates a general error).</summary>
        public byte ErrorCode { get; set; }

        /// <summary>Framing capabilities of the responder.</summary>
        public PptpFramingCapability FramingCapabilities { get; set; }

        /// <summary>Bearer capabilities of the responder.</summary>
        public PptpBearerCapability BearerCapabilities { get; set; }

        /// <summary>Maximum number of PPTP sessions the responder supports.</summary>
        public ushort MaximumChannels { get; set; }

        /// <summary>Firmware/driver revision of the responder.</summary>
        public ushort FirmwareRevision { get; set; }

        /// <summary>Host name of the responder.</summary>
        public string HostName { get; set; } = string.Empty;

        /// <summary>Vendor / model string of the responder.</summary>
        public string VendorName { get; set; } = string.Empty;
    }
}
