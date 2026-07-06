using System;
using System.Collections.Generic;
using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Config
{
    /// <summary>
    /// A static L2TPv3 Ethernet-pseudowire (RFC 3931 + RFC 4719) endpoint configuration — the parts a client needs to bring
    /// an L2-over-UDP pseudowire up in <b>static/unmanaged</b> mode. There is no control plane: the two peers configure the
    /// Session IDs and the shared Cookie up front (like <c>ip l2tp add session ... pwtype ethernet</c>), so the overlay IP /
    /// prefix / routes / MTU are all known ahead of time and map straight to a <see cref="TunnelConfig"/> (no DHCP). Frames
    /// are carried under a static session; the remote unicast host:port comes from the connect-time <see cref="VpnEndpoint"/>
    /// (not this config) — mirroring how the VXLAN / Geneve drivers take their remote endpoint from the endpoint. Nothing
    /// here is encrypted — L2TPv3 data is a bare header (RFC 3931).
    /// </summary>
    public sealed class L2tpv3EthConfig
    {
        /// <summary>
        /// The <b>local</b> Session ID this endpoint listens on: an inbound data message must carry this value (RFC 3931 §4.1).
        /// Required; non-zero and ≤ <see cref="L2tpv3DataHeader.MaxSessionId"/> (the top bit is the T/control flag).
        /// </summary>
        public required uint LocalSessionId { get; init; }

        /// <summary>
        /// The <b>remote</b> (peer) Session ID this endpoint stamps on every outbound data message so the peer recognises it
        /// (the peer's local session id). Required; non-zero and ≤ <see cref="L2tpv3DataHeader.MaxSessionId"/>.
        /// </summary>
        public required uint RemoteSessionId { get; init; }

        /// <summary>
        /// The shared session Cookie (0, 4 or 8 bytes) — stamped on egress and verified on ingress for anti-spoofing
        /// (RFC 3931 §4.1). Both peers configure the same value. Null or empty means no cookie (0 bytes). Defaults to none.
        /// </summary>
        public byte[]? Cookie { get; init; }

        /// <summary>
        /// When true, egress prepends a 4-byte Default L2-Specific Sublayer (RFC 3931 §4.6) carrying a 24-bit Sequence Number
        /// and ingress expects one. Both peers must agree. Defaults to false (the minimal static pseudowire, no sublayer).
        /// </summary>
        public bool EnableSequencing { get; init; }

        /// <summary>The remote UDP port. Defaults to <see cref="L2tpv3DataHeader.DefaultPort"/> (1701).</summary>
        public int Port { get; init; } = L2tpv3DataHeader.DefaultPort;

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
        /// The tunnel MTU; defaults to <see cref="L2tpv3EthDriverConstants.DefaultMtu"/> (1400 — L2TPv3-over-UDP adds outer
        /// overhead on a 1500-byte path).
        /// </summary>
        public int Mtu { get; init; } = L2tpv3EthDriverConstants.DefaultMtu;

        /// <summary>The session Cookie as a span (empty when no cookie is configured).</summary>
        internal ReadOnlyMemory<byte> CookieBytes => Cookie ?? Array.Empty<byte>();

        /// <summary>
        /// Resolves the configured local MAC, or a random locally-administered unicast MAC when <see cref="LocalMac"/> is
        /// null. Validates the Session IDs and the Cookie length.
        /// </summary>
        /// <exception cref="ArgumentException"><see cref="LocalMac"/> is set but not 6 bytes.</exception>
        public MacAddress ResolveLocalMac(Action<byte[]> fillRandom)
        {
            Validate();
            if (LocalMac is not null)
            {
                if (LocalMac.Length != MacAddress.Size)
                    throw new ArgumentException($"L2tpv3EthConfig.LocalMac must be {MacAddress.Size} bytes.", nameof(LocalMac));
                return MacAddress.FromBytes(LocalMac);
            }
            byte[] bytes = new byte[MacAddress.Size];
            fillRandom(bytes);
            bytes[0] = (byte)((bytes[0] & 0xFE) | 0x02);   // I/G bit clear (unicast), U/L bit set (locally administered)
            return MacAddress.FromBytes(bytes);
        }

        /// <summary>
        /// Projects this configuration onto a <see cref="TunnelConfig"/> — the same shape every driver hands to the userspace
        /// IP stack, filled directly from the static config (L2TPv3 static mode does no in-tunnel negotiation). The MTU
        /// reported here is the configured MTU; the bridge subtracts the 14-byte Ethernet header when the stack binds.
        /// </summary>
        public TunnelConfig ToTunnelConfig()
        {
            Validate();
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

        /// <summary>Validates the Session IDs (non-zero, top bit clear) and the Cookie length (0/4/8).</summary>
        /// <exception cref="ArgumentOutOfRangeException">A Session ID is 0 / has the top bit set, or the Cookie length is not 0/4/8.</exception>
        void Validate()
        {
            if (!L2tpv3DataHeader.IsValidDataSessionId(LocalSessionId))
                throw new ArgumentOutOfRangeException(nameof(LocalSessionId), LocalSessionId, "An L2TPv3 data Session ID must be non-zero and ≤ 0x7FFFFFFF (the top bit is the T/control flag).");
            if (!L2tpv3DataHeader.IsValidDataSessionId(RemoteSessionId))
                throw new ArgumentOutOfRangeException(nameof(RemoteSessionId), RemoteSessionId, "An L2TPv3 data Session ID must be non-zero and ≤ 0x7FFFFFFF (the top bit is the T/control flag).");
            if (!L2tpv3DataHeader.IsValidCookieLength(CookieBytes.Length))
                throw new ArgumentOutOfRangeException(nameof(Cookie), CookieBytes.Length, "An L2TPv3 Cookie is 0, 4 or 8 bytes.");
        }
    }
}
