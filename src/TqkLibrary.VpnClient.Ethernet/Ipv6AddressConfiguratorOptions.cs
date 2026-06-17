using System;
using TqkLibrary.VpnClient.Ethernet.Enums;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// Tunables for <see cref="Ipv6AddressConfigurator"/>: how to derive the SLAAC interface identifier, how long to
    /// wait for a Router Advertisement (and how often to re-send a Router Solicitation to elicit one), the DHCPv6
    /// SOLICIT/REQUEST reply timeout and attempt budget, and the MTU recorded on the produced
    /// <see cref="Abstractions.Drivers.Models.TunnelConfig"/>. Mirrors <see cref="DhcpV4ConfiguratorOptions"/> /
    /// <see cref="NdiscResolverOptions"/>; tests use short timeouts so the time-out paths run fast.
    /// </summary>
    /// <remarks>
    /// Plain class (no <c>record</c>/<c>init</c>) so it compiles on <c>netstandard2.0</c>; all values are
    /// constructor-set and read-only, so <see cref="Default"/> is safe to share.
    /// </remarks>
    public sealed class Ipv6AddressConfiguratorOptions
    {
        /// <summary>How to derive the 64-bit interface identifier of a SLAAC address (RFC 4862 §5.5.3).</summary>
        public SlaacInterfaceIdentifierMode InterfaceIdentifierMode { get; }

        /// <summary>How long to wait for a Router Advertisement after each Router Solicitation before retrying.</summary>
        public TimeSpan RouterAdvertisementTimeout { get; }

        /// <summary>Number of Router Solicitations sent (RFC 4861 §6.3.7) before SLAAC gives up.</summary>
        public int RouterSolicitationAttempts { get; }

        /// <summary>How long to wait for a DHCPv6 ADVERTISE/REPLY before retransmitting the SOLICIT/REQUEST.</summary>
        public TimeSpan DhcpReplyTimeout { get; }

        /// <summary>Number of DHCPv6 SOLICIT (or REQUEST) messages sent before a phase gives up.</summary>
        public int DhcpMaxAttempts { get; }

        /// <summary>
        /// When the RA does not request stateful DHCPv6 (M flag clear) but still carries no autonomous prefix, whether to
        /// fall back to a DHCPv6 SOLICIT anyway. Off by default — RFC 8415 leaves stateful DHCPv6 to the M/O flags.
        /// </summary>
        public bool ForceDhcp { get; }

        /// <summary>The MTU recorded on the produced <see cref="Abstractions.Drivers.Models.TunnelConfig"/>.</summary>
        public int Mtu { get; }

        /// <summary>Creates the options; any timing argument left <c>null</c> takes its default.</summary>
        public Ipv6AddressConfiguratorOptions(
            SlaacInterfaceIdentifierMode interfaceIdentifierMode = SlaacInterfaceIdentifierMode.ModifiedEui64,
            TimeSpan? routerAdvertisementTimeout = null,
            int routerSolicitationAttempts = 3,
            TimeSpan? dhcpReplyTimeout = null,
            int dhcpMaxAttempts = 4,
            bool forceDhcp = false,
            int mtu = 1500)
        {
            InterfaceIdentifierMode = interfaceIdentifierMode;
            RouterAdvertisementTimeout = routerAdvertisementTimeout ?? TimeSpan.FromSeconds(2);
            RouterSolicitationAttempts = routerSolicitationAttempts < 1 ? 1 : routerSolicitationAttempts;
            DhcpReplyTimeout = dhcpReplyTimeout ?? TimeSpan.FromSeconds(2);
            DhcpMaxAttempts = dhcpMaxAttempts < 1 ? 1 : dhcpMaxAttempts;
            ForceDhcp = forceDhcp;
            Mtu = mtu < 1280 ? 1280 : mtu;   // IPv6 minimum link MTU (RFC 8200 §5)
        }

        /// <summary>Defaults (EUI-64, 2s RA timeout / 3 RS, 2s DHCP timeout / 4 attempts, no force-DHCP, MTU 1500).</summary>
        public static Ipv6AddressConfiguratorOptions Default { get; } = new Ipv6AddressConfiguratorOptions();
    }
}
