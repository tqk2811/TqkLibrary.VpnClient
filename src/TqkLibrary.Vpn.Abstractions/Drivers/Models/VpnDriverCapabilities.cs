using TqkLibrary.Vpn.Abstractions.Drivers.Enums;

namespace TqkLibrary.Vpn.Abstractions.Drivers.Models
{
    /// <summary>
    /// What a protocol driver can do. The façade reads this to negotiate before connecting and to refuse
    /// gracefully (e.g. <see cref="RequiresElevation"/> without admin/root → <c>VpnElevationRequiredException</c>).
    /// </summary>
    public sealed class VpnDriverCapabilities
    {
        /// <summary>L3 (IP) or L2 (Ethernet) output.</summary>
        public VpnLinkLayer LinkLayer { get; set; } = VpnLinkLayer.L3Ip;

        /// <summary>Whether one connection can host more than one virtual IP endpoint.</summary>
        public bool SupportsMultiHost { get; set; }

        /// <summary>How multi-host is realized, when supported.</summary>
        public MultiHostModel MultiHostModel { get; set; } = MultiHostModel.None;

        /// <summary>True if the driver carries PPP (shares the PPP engine: L2TP, SSTP, PPTP, Fortinet, F5).</summary>
        public bool UsesPpp { get; set; }

        /// <summary>Transports the driver can use.</summary>
        public VpnTransportKind TransportKinds { get; set; }

        /// <summary>Security layers the driver supports.</summary>
        public VpnSecurityKind SecurityKinds { get; set; }

        /// <summary>Authentication methods the driver supports.</summary>
        public VpnAuthMethod AuthMethods { get; set; }

        /// <summary>How the tunnel address is assigned.</summary>
        public AddressAssignment AddressAssignment { get; set; } = AddressAssignment.Ipcp;

        /// <summary>True if the driver needs a raw IP socket (proto-less: GRE/ESP/EtherIP/L2TPv3).</summary>
        public bool RequiresRawIpSocket { get; set; }

        /// <summary>True if the driver needs elevated privilege (admin/root/CAP_NET_RAW) — e.g. raw-IP drivers.</summary>
        public bool RequiresElevation { get; set; }
    }
}
