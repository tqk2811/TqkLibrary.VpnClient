using System;
using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// What a <see cref="VirtualHost"/> knows about its own link: the prefix it sits on and the router to hand
    /// everything else to. <see cref="SelectNextHop"/> turns a packet's destination into the address the neighbor
    /// layer should resolve — the destination itself when it is on-link, the default gateway when it is not.
    /// <para>
    /// This is the difference between a tunnel that comes up and a tunnel that carries traffic. Without it a host
    /// ARPs for the destination of every packet, so a public address goes unanswered (nothing on the segment owns
    /// it), the resolve times out and the packet is dropped in silence — the tunnel leases an address, answers DNS
    /// from a server that happens to be on-link, and drops every connection attempt with nothing in the log.
    /// </para>
    /// <para>
    /// The table starts empty and an empty table is a no-op (every destination is its own next hop), so a host on an
    /// overlay LAN with no router keeps the plain on-link behaviour. A driver fills it once its lease lands — see
    /// <see cref="Apply"/>. Mutable on purpose, the same way <see cref="ArpResolver.SetLocalAddress"/> is: the host
    /// is built before DHCP runs, so the routing it will use is not known until afterwards.
    /// </para>
    /// </summary>
    /// <remarks>
    /// Deliberately not a full routing table: one on-link prefix and one default gateway per family, which is what a
    /// DHCP lease or a Router Advertisement actually hands out. Per-destination routes (<see cref="TunnelConfig.Routes"/>)
    /// are a split-tunnel concern for a layer that owns policy, not for the bridge.
    /// </remarks>
    public sealed class NextHopTable
    {
        readonly object _sync = new object();
        Entry _v4;
        Entry _v6;

        /// <summary>The IPv4 default gateway, or <c>null</c> when none is known.</summary>
        public IPAddress? Gateway
        {
            get { lock (_sync) return _v4.Gateway; }
        }

        /// <summary>The IPv6 default gateway, or <c>null</c> when none is known.</summary>
        public IPAddress? GatewayV6
        {
            get { lock (_sync) return _v6.Gateway; }
        }

        /// <summary>
        /// Fills the table from a session's <paramref name="config"/>: the IPv4 leg from
        /// <see cref="TunnelConfig.AssignedAddress"/>/<see cref="TunnelConfig.PrefixLength"/>/<see cref="TunnelConfig.Gateway"/>
        /// and the IPv6 leg from their <c>V6</c> counterparts. A family the config says nothing about is left alone,
        /// so calling this again after IPv6 autoconfiguration does not erase the IPv4 routing.
        /// </summary>
        public void Apply(TunnelConfig config)
        {
            if (config is null)
                throw new ArgumentNullException(nameof(config));

            if (config.AssignedAddress != null && config.AssignedAddress.AddressFamily == AddressFamily.InterNetwork)
                SetIpv4(config.AssignedAddress, config.PrefixLength, config.Gateway);
            if (config.AssignedAddressV6 != null && config.AssignedAddressV6.AddressFamily == AddressFamily.InterNetworkV6)
                SetIpv6(config.AssignedAddressV6, config.PrefixLengthV6, config.GatewayV6);
        }

        /// <summary>
        /// Sets the IPv4 link: this host sits at <paramref name="localAddress"/> on a
        /// <paramref name="prefixLength"/>-bit prefix, reaching everything else through <paramref name="gateway"/>
        /// (<c>null</c> for an overlay with no router).
        /// </summary>
        /// <exception cref="ArgumentException"><paramref name="localAddress"/> is not IPv4.</exception>
        public void SetIpv4(IPAddress localAddress, int prefixLength, IPAddress? gateway)
            => Set(ref _v4, localAddress, prefixLength, gateway, AddressFamily.InterNetwork, 32);

        /// <summary>The IPv6 counterpart of <see cref="SetIpv4"/>.</summary>
        /// <exception cref="ArgumentException"><paramref name="localAddress"/> is not IPv6.</exception>
        public void SetIpv6(IPAddress localAddress, int prefixLength, IPAddress? gateway)
            => Set(ref _v6, localAddress, prefixLength, gateway, AddressFamily.InterNetworkV6, 128);

        /// <summary>
        /// The address to resolve to a MAC in order to send a packet to <paramref name="destination"/>: the
        /// destination when it is on-link (or when this table knows nothing about its family), the default gateway
        /// otherwise. Never <c>null</c> — a caller with no routing still gets today's on-link answer.
        /// </summary>
        public IPAddress SelectNextHop(IPAddress destination)
        {
            if (destination is null)
                throw new ArgumentNullException(nameof(destination));

            Entry entry;
            lock (_sync)
                entry = destination.AddressFamily == AddressFamily.InterNetworkV6 ? _v6 : _v4;

            if (entry.Gateway is null || entry.Local is null)
                return destination;                      // no router to send it to — on-link is the only answer
            if (entry.Local.AddressFamily != destination.AddressFamily)
                return destination;                      // the table's family does not match this packet
            if (IsLinkScoped(destination))
                return destination;                      // link-local, multicast and broadcast never leave the link
            if (SamePrefix(entry.Local, destination, entry.PrefixLength))
                return destination;                      // on-link: the destination answers for itself

            return entry.Gateway;
        }

        // Multicast and broadcast are delivered on the link itself, and an IPv6 link-local address is only
        // meaningful there — sending any of them to a router would be wrong even when one is configured.
        static bool IsLinkScoped(IPAddress address)
        {
            byte[] bytes = address.GetAddressBytes();
            if (address.AddressFamily == AddressFamily.InterNetwork)
                return bytes[0] >= 224                                                // 224.0.0.0/4 multicast + 240/4
                    || (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255);
            return bytes[0] == 0xFF                                                   // ff00::/8 multicast
                || (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80);                   // fe80::/10 link-local
        }

        /// <summary>Whether two same-family addresses share their leading <paramref name="prefixLength"/> bits.</summary>
        public static bool SamePrefix(IPAddress a, IPAddress b, int prefixLength)
        {
            if (a is null) throw new ArgumentNullException(nameof(a));
            if (b is null) throw new ArgumentNullException(nameof(b));
            if (a.AddressFamily != b.AddressFamily)
                return false;

            byte[] left = a.GetAddressBytes();
            byte[] right = b.GetAddressBytes();
            if (prefixLength < 0 || prefixLength > left.Length * 8)
                return false;

            int wholeBytes = prefixLength / 8;
            for (int i = 0; i < wholeBytes; i++)
                if (left[i] != right[i])
                    return false;

            int remainingBits = prefixLength % 8;
            if (remainingBits == 0)
                return true;

            int mask = 0xFF << (8 - remainingBits);
            return (left[wholeBytes] & mask) == (right[wholeBytes] & mask);
        }

        void Set(ref Entry slot, IPAddress localAddress, int prefixLength, IPAddress? gateway, AddressFamily family, int maxPrefix)
        {
            if (localAddress is null)
                throw new ArgumentNullException(nameof(localAddress));
            if (localAddress.AddressFamily != family)
                throw new ArgumentException($"The local address must be {family}.", nameof(localAddress));
            if (gateway != null && gateway.AddressFamily != family)
                throw new ArgumentException($"The gateway must be {family}.", nameof(gateway));

            int clamped = prefixLength < 0 ? 0 : prefixLength > maxPrefix ? maxPrefix : prefixLength;
            lock (_sync)
                slot = new Entry(localAddress, clamped, gateway);
        }

        readonly struct Entry
        {
            public readonly IPAddress? Local;
            public readonly int PrefixLength;
            public readonly IPAddress? Gateway;

            public Entry(IPAddress? local, int prefixLength, IPAddress? gateway)
            {
                Local = local;
                PrefixLength = prefixLength;
                Gateway = gateway;
            }
        }
    }
}
