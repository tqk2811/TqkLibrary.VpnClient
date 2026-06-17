using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;

namespace TqkLibrary.VpnClient.Pptp.Models
{
    /// <summary>
    /// Start-Control-Connection-Request (RFC 2637 §2.1) — sent by the PAC/PNS to establish the control
    /// connection. Body (after the common header + Control Message Type + Reserved0):
    /// ProtocolVersion(2), Reserved1(2), FramingCapabilities(4), BearerCapabilities(4), MaximumChannels(2),
    /// FirmwareRevision(2), HostName(64, ASCII NUL-padded), VendorName(64, ASCII NUL-padded).
    /// </summary>
    public sealed class StartControlConnectionRequest : IPptpControlMessage
    {
        /// <inheritdoc/>
        public PptpControlMessageType ControlMessageType => PptpControlMessageType.StartControlConnectionRequest;

        /// <summary>PPTP protocol version (RFC 2637 mandates 0x0100 = version 1.0).</summary>
        public ushort ProtocolVersion { get; set; } = 0x0100;

        /// <summary>Framing capabilities advertised by the sender.</summary>
        public PptpFramingCapability FramingCapabilities { get; set; } = PptpFramingCapability.Asynchronous | PptpFramingCapability.Synchronous;

        /// <summary>Bearer capabilities advertised by the sender.</summary>
        public PptpBearerCapability BearerCapabilities { get; set; } = PptpBearerCapability.Analog | PptpBearerCapability.Digital;

        /// <summary>Maximum number of PPTP sessions the sender supports (0 if irrelevant to PNS).</summary>
        public ushort MaximumChannels { get; set; }

        /// <summary>Firmware/driver revision of the sender.</summary>
        public ushort FirmwareRevision { get; set; }

        /// <summary>Host name (DNS) — encoded ASCII, NUL-padded to 64 bytes on the wire.</summary>
        public string HostName { get; set; } = string.Empty;

        /// <summary>Vendor / model string — encoded ASCII, NUL-padded to 64 bytes on the wire.</summary>
        public string VendorName { get; set; } = string.Empty;
    }
}
