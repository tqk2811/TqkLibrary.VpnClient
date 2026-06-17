using System;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// A dual-stack <see cref="IAddressConfigurator"/> that runs an IPv4 configurator (DHCPv4, L2.5) and an IPv6
    /// configurator (SLAAC + DHCPv6, L2.6) and merges their results into one <see cref="TunnelConfig"/> carrying both
    /// families — the address-config counterpart of <see cref="DualStackNeighborResolver"/>. A host on an
    /// <see cref="EthernetAdapter"/> takes a single <see cref="IAddressConfigurator"/>, so this composite is what lets one
    /// station lease its IPv4 address and configure its IPv6 address at once.
    /// <para>
    /// The IPv4 leg fills <see cref="TunnelConfig.AssignedAddress"/>/<see cref="TunnelConfig.PrefixLength"/>; the IPv6 leg
    /// fills <see cref="TunnelConfig.AssignedAddressV6"/>/<see cref="TunnelConfig.PrefixLengthV6"/>. DNS servers and routes
    /// from both legs are concatenated, and the MTU is the smaller of the two. Disposal cascades to the inner
    /// configurators when <see cref="OwnsInnerConfigurators"/> is set (default).
    /// </para>
    /// </summary>
    public sealed class DualStackAddressConfigurator : IAddressConfigurator, IAsyncDisposable
    {
        readonly IAddressConfigurator _ipv4;
        readonly IAddressConfigurator _ipv6;
        int _disposed;

        /// <summary>
        /// Creates a dual-stack configurator running <paramref name="ipv4"/> (DHCPv4) then <paramref name="ipv6"/>
        /// (SLAAC/DHCPv6) and merging both into one <see cref="TunnelConfig"/>.
        /// </summary>
        /// <param name="ipv4">The IPv4 configurator — typically a <see cref="DhcpV4Configurator"/>.</param>
        /// <param name="ipv6">The IPv6 configurator — typically an <see cref="Ipv6AddressConfigurator"/>.</param>
        /// <param name="ownsInnerConfigurators">
        /// When <c>true</c> (default), <see cref="DisposeAsync"/> disposes both inner configurators (if they are
        /// <see cref="IAsyncDisposable"/>). Set <c>false</c> if the caller owns their lifetime.
        /// </param>
        public DualStackAddressConfigurator(IAddressConfigurator ipv4, IAddressConfigurator ipv6, bool ownsInnerConfigurators = true)
        {
            _ipv4 = ipv4 ?? throw new ArgumentNullException(nameof(ipv4));
            _ipv6 = ipv6 ?? throw new ArgumentNullException(nameof(ipv6));
            OwnsInnerConfigurators = ownsInnerConfigurators;
        }

        /// <summary>The IPv4 (DHCPv4) configurator.</summary>
        public IAddressConfigurator Ipv4 => _ipv4;

        /// <summary>The IPv6 (SLAAC + DHCPv6) configurator.</summary>
        public IAddressConfigurator Ipv6 => _ipv6;

        /// <summary>Whether disposing this configurator also disposes the two inner configurators.</summary>
        public bool OwnsInnerConfigurators { get; }

        /// <inheritdoc/>
        public async ValueTask<TunnelConfig> ConfigureAsync(CancellationToken cancellationToken = default)
        {
            TunnelConfig v4 = await _ipv4.ConfigureAsync(cancellationToken).ConfigureAwait(false);
            TunnelConfig v6 = await _ipv6.ConfigureAsync(cancellationToken).ConfigureAwait(false);

            var merged = new TunnelConfig
            {
                AssignedAddress = v4.AssignedAddress,
                PrefixLength = v4.PrefixLength,
                AssignedAddressV6 = v6.AssignedAddressV6,
                PrefixLengthV6 = v6.PrefixLengthV6,
                Mtu = Math.Min(v4.Mtu, v6.Mtu),
            };
            foreach (var dns in v4.DnsServers)
                merged.DnsServers.Add(dns);
            foreach (var dns in v6.DnsServers)
                merged.DnsServers.Add(dns);
            foreach (var route in v4.Routes)
                merged.Routes.Add(route);
            foreach (var route in v6.Routes)
                merged.Routes.Add(route);
            return merged;
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;
            if (!OwnsInnerConfigurators)
                return;
            if (_ipv4 is IAsyncDisposable v4)
                await v4.DisposeAsync().ConfigureAwait(false);
            if (_ipv6 is IAsyncDisposable v6)
                await v6.DisposeAsync().ConfigureAwait(false);
        }
    }
}
