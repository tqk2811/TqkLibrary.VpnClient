using System;
using System.Collections.Generic;
using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.EoGre.Enums;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.EoGre.Config
{
    /// <summary>
    /// A static EoGRE / NVGRE endpoint configuration — the parts a client needs to bring an L2-over-UDP overlay up over
    /// GRE-in-UDP (RFC 8086). There is no control plane: no registration, no keepalive, no address negotiation, so the
    /// overlay IP / prefix / routes / MTU are all known up front and map straight to a <see cref="TunnelConfig"/> (no DHCP).
    /// Frames are carried behind a standard GRE header (protocol type 0x6558) inside a UDP payload; the remote unicast
    /// host:port comes from the connect-time <see cref="VpnEndpoint"/> (not this config) — mirroring the VXLAN / Geneve
    /// drivers. Nothing here is encrypted — EoGRE/NVGRE only tunnel the L2 frame (RFC 2784/2890 + RFC 7637).
    /// </summary>
    public sealed class EoGreConfig
    {
        /// <summary>
        /// The 24-bit Virtual Subnet ID carried in the GRE Key (RFC 7637 NVGRE). In <see cref="EoGreMode.EoGre"/> this is
        /// optional (null ⇒ no Key / plain GRETAP); in <see cref="EoGreMode.Nvgre"/> it is required (0..0xFFFFFF).
        /// </summary>
        public uint? Vsid { get; init; }

        /// <summary>The 8-bit FlowID packed into the low byte of the GRE Key alongside the VSID (RFC 7637). Default 0.</summary>
        public byte FlowId { get; init; }

        /// <summary>The remote UDP port carrying the GRE header. Defaults to <see cref="EoGreCodec.DefaultPort"/> (4754, RFC 8086).</summary>
        public int Port { get; init; } = EoGreCodec.DefaultPort;

        /// <summary>The static overlay IPv4 address this endpoint uses on the L2 segment. Required.</summary>
        public required IPAddress OverlayAddress { get; init; }

        /// <summary>The overlay subnet prefix length (e.g. /24). Defaults to 24.</summary>
        public int PrefixLength { get; init; } = 24;

        /// <summary>
        /// This endpoint's 6-byte MAC on the L2 segment. When null a random locally-administered unicast MAC is generated
        /// (I/G bit clear, U/L bit set) — what a fresh virtual interface does when no MAC is pinned.
        /// </summary>
        public byte[]? LocalMac { get; init; }

        /// <summary>
        /// When true, every outbound GRE packet carries an RFC 2784 Checksum (C bit). Ignored (forced off) in
        /// <see cref="EoGreMode.Nvgre"/> — NVGRE (RFC 7637) forbids the Checksum. Default false.
        /// </summary>
        public bool EnableChecksum { get; init; }

        /// <summary>
        /// When true, every outbound GRE packet carries an incrementing RFC 2890 Sequence Number (S bit). Ignored (forced
        /// off) in <see cref="EoGreMode.Nvgre"/> — NVGRE (RFC 7637) forbids the Sequence Number. Default false.
        /// </summary>
        public bool EnableSequence { get; init; }

        /// <summary>
        /// When true, an inbound datagram whose GRE Key VSID does not match <see cref="Vsid"/> is dropped. Always on in
        /// <see cref="EoGreMode.Nvgre"/> (the VSID is the tenant selector); optional in <see cref="EoGreMode.EoGre"/>. Default false.
        /// </summary>
        public bool StrictVsid { get; init; }

        /// <summary>DNS servers to use inside the tunnel; empty when none is configured.</summary>
        public IReadOnlyList<IPAddress> DnsServers { get; init; } = Array.Empty<IPAddress>();

        /// <summary>
        /// The overlay routes reachable through the tunnel (CIDR text). Defaults to the overlay subnet derived from
        /// <see cref="OverlayAddress"/>/<see cref="PrefixLength"/> when empty.
        /// </summary>
        public IReadOnlyList<string> Routes { get; init; } = Array.Empty<string>();

        /// <summary>
        /// The tunnel MTU; defaults to <see cref="EoGreDriverConstants.DefaultMtu"/> (1400 — GRE-in-UDP-TEB adds ≈46 bytes
        /// of outer overhead on a 1500-byte path).
        /// </summary>
        public int Mtu { get; init; } = EoGreDriverConstants.DefaultMtu;

        /// <summary>
        /// Validates the configuration against the driver <paramref name="mode"/>: the VSID (when present) fits 24 bits, and
        /// in <see cref="EoGreMode.Nvgre"/> a VSID is present (RFC 7637 requires one).
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="Vsid"/> exceeds 24 bits.</exception>
        /// <exception cref="ArgumentException"><paramref name="mode"/> is NVGRE but no <see cref="Vsid"/> is set.</exception>
        public void Validate(EoGreMode mode)
        {
            if (Vsid.HasValue && Vsid.Value > EoGreCodec.MaxVsid)
                throw new ArgumentOutOfRangeException(nameof(Vsid), Vsid, "An NVGRE VSID is a 24-bit value (0..0xFFFFFF).");
            if (mode == EoGreMode.Nvgre && !Vsid.HasValue)
                throw new ArgumentException("NVGRE (RFC 7637) requires a 24-bit VSID; set EoGreConfig.Vsid.", nameof(Vsid));
        }

        /// <summary>
        /// Resolves the configured local MAC, or a random locally-administered unicast MAC when <see cref="LocalMac"/> is
        /// null. Validates the VSID (when present) is a 24-bit value.
        /// </summary>
        /// <exception cref="ArgumentException"><see cref="LocalMac"/> is set but not 6 bytes.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="Vsid"/> exceeds 24 bits.</exception>
        public MacAddress ResolveLocalMac(Action<byte[]> fillRandom)
        {
            if (Vsid.HasValue && Vsid.Value > EoGreCodec.MaxVsid)
                throw new ArgumentOutOfRangeException(nameof(Vsid), Vsid, "An NVGRE VSID is a 24-bit value (0..0xFFFFFF).");
            if (LocalMac is not null)
            {
                if (LocalMac.Length != MacAddress.Size)
                    throw new ArgumentException($"EoGreConfig.LocalMac must be {MacAddress.Size} bytes.", nameof(LocalMac));
                return MacAddress.FromBytes(LocalMac);
            }
            byte[] bytes = new byte[MacAddress.Size];
            fillRandom(bytes);
            bytes[0] = (byte)((bytes[0] & 0xFE) | 0x02);   // I/G bit clear (unicast), U/L bit set (locally administered)
            return MacAddress.FromBytes(bytes);
        }

        /// <summary>
        /// Projects this configuration onto a <see cref="TunnelConfig"/> — the same shape every driver hands to the
        /// userspace IP stack, filled directly from the static config (EoGRE/NVGRE do no in-tunnel negotiation). The MTU
        /// reported here is the configured MTU; the bridge subtracts the 14-byte Ethernet header when the stack binds.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="Vsid"/> exceeds 24 bits.</exception>
        public TunnelConfig ToTunnelConfig()
        {
            if (Vsid.HasValue && Vsid.Value > EoGreCodec.MaxVsid)
                throw new ArgumentOutOfRangeException(nameof(Vsid), Vsid, "An NVGRE VSID is a 24-bit value (0..0xFFFFFF).");

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
