using System;
using System.Collections.Generic;
using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.Vxlan.Config
{
    /// <summary>
    /// A static VXLAN endpoint configuration — the parts of an <c>ip link add type vxlan …</c> a client needs to bring an
    /// L2-over-UDP overlay up. VXLAN has no control plane: there is no registration, no keepalive, no address negotiation,
    /// so the overlay IP / prefix / routes / MTU are all known up front and map straight to a <see cref="TunnelConfig"/>
    /// (no DHCP). Frames are carried under the 24-bit <see cref="Vni"/>; the remote unicast VTEP host:port comes from the
    /// connect-time <see cref="VpnEndpoint"/> (not this config) — mirroring how the n2n driver takes its supernode host
    /// from the endpoint. Nothing here is encrypted — VXLAN is a bare header (RFC 7348).
    /// </summary>
    public sealed class VxlanConfig
    {
        /// <summary>The 24-bit VXLAN Network Identifier (VNI) every VTEP on this overlay shares. Required (0..0xFFFFFF).</summary>
        public required uint Vni { get; init; }

        /// <summary>The remote VTEP UDP port (VXLAN's <c>dstport</c>). Defaults to <see cref="VxlanCodec.DefaultPort"/> (4789).</summary>
        public int Port { get; init; } = VxlanCodec.DefaultPort;

        /// <summary>The static overlay IPv4 address this endpoint uses on the L2 segment. Required.</summary>
        public required IPAddress OverlayAddress { get; init; }

        /// <summary>The overlay subnet prefix length (e.g. /24). Defaults to 24.</summary>
        public int PrefixLength { get; init; } = 24;

        /// <summary>
        /// This endpoint's 6-byte MAC on the L2 segment. When null a random locally-administered unicast MAC is generated
        /// (I/G bit clear, U/L bit set) — what a fresh virtual interface does when no MAC is pinned.
        /// </summary>
        public byte[]? LocalMac { get; init; }

        /// <summary>DNS servers to use inside the tunnel; empty when none is configured.</summary>
        public IReadOnlyList<IPAddress> DnsServers { get; init; } = Array.Empty<IPAddress>();

        /// <summary>
        /// The overlay routes reachable through the tunnel (CIDR text). Defaults to the overlay subnet derived from
        /// <see cref="OverlayAddress"/>/<see cref="PrefixLength"/> when empty.
        /// </summary>
        public IReadOnlyList<string> Routes { get; init; } = Array.Empty<string>();

        /// <summary>
        /// The tunnel MTU; defaults to <see cref="VxlanDriverConstants.DefaultMtu"/> (1400 — VXLAN adds ~50 bytes of
        /// outer overhead on a 1500-byte path).
        /// </summary>
        public int Mtu { get; init; } = VxlanDriverConstants.DefaultMtu;

        /// <summary>
        /// Resolves the configured local MAC, or a random locally-administered unicast MAC when <see cref="LocalMac"/> is
        /// null. Validates the VNI is a 24-bit value.
        /// </summary>
        /// <exception cref="ArgumentException"><see cref="LocalMac"/> is set but not 6 bytes.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="Vni"/> exceeds 24 bits.</exception>
        public MacAddress ResolveLocalMac(Action<byte[]> fillRandom)
        {
            if (Vni > VxlanCodec.MaxVni)
                throw new ArgumentOutOfRangeException(nameof(Vni), Vni, "A VXLAN VNI is a 24-bit value (0..0xFFFFFF).");
            if (LocalMac is not null)
            {
                if (LocalMac.Length != MacAddress.Size)
                    throw new ArgumentException($"VxlanConfig.LocalMac must be {MacAddress.Size} bytes.", nameof(LocalMac));
                return MacAddress.FromBytes(LocalMac);
            }
            byte[] bytes = new byte[MacAddress.Size];
            fillRandom(bytes);
            bytes[0] = (byte)((bytes[0] & 0xFE) | 0x02);   // I/G bit clear (unicast), U/L bit set (locally administered)
            return MacAddress.FromBytes(bytes);
        }

        /// <summary>
        /// Projects this configuration onto a <see cref="TunnelConfig"/> — the same shape every driver hands to the
        /// userspace IP stack, filled directly from the static config (VXLAN does no in-tunnel negotiation). The MTU
        /// reported here is the configured MTU; the bridge subtracts the 14-byte Ethernet header when the stack binds.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="Vni"/> exceeds 24 bits.</exception>
        public TunnelConfig ToTunnelConfig()
        {
            if (Vni > VxlanCodec.MaxVni)
                throw new ArgumentOutOfRangeException(nameof(Vni), Vni, "A VXLAN VNI is a 24-bit value (0..0xFFFFFF).");

            var config = new TunnelConfig
            {
                AssignedAddress = OverlayAddress,
                PrefixLength = PrefixLength,
                Mtu = Mtu,
            };
            foreach (IPAddress dns in DnsServers) config.DnsServers.Add(dns);
            if (Routes.Count > 0)
            {
                foreach (string route in Routes) config.Routes.Add(route);
            }
            else
            {
                config.Routes.Add($"{OverlayAddress}/{PrefixLength}");
            }
            return config;
        }
    }
}
