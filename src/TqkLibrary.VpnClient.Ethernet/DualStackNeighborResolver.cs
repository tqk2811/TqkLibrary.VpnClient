using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// A dual-stack <see cref="INeighborResolver"/> for a host that speaks both IPv4 and IPv6 on the same
    /// <see cref="VirtualHost"/>: it routes each <see cref="ResolveAsync"/> to the per-family resolver by the next-hop's
    /// <see cref="AddressFamily"/> — IPv4 next-hops go to the ARP resolver (L2.3), IPv6 next-hops to the NDISC resolver
    /// (L2.4). A <see cref="VirtualHost"/> holds exactly one resolver, so this composite is what lets one host carry both
    /// families at once (the v4 path's <see cref="ArpResolver"/> already returns <c>null</c> for v6 and vice-versa, so
    /// without this composite a host could only resolve one family).
    /// <para>
    /// The two inner resolvers each still own their own switch-port plumbing and inbound-frame seam (ARP rides
    /// <see cref="VirtualHost.InboundNonIpFrame"/>; NDISC rides <see cref="VirtualHost.InboundIpPacket"/>) — this type only
    /// fans the egress <see cref="ResolveAsync"/> call out by family; it does not re-wire the seams. Disposal cascades to
    /// the inner resolvers when <see cref="OwnsInnerResolvers"/> is set (default).
    /// </para>
    /// </summary>
    public sealed class DualStackNeighborResolver : INeighborResolver, IAsyncDisposable
    {
        readonly INeighborResolver _ipv4;
        readonly INeighborResolver _ipv6;
        int _disposed;

        /// <summary>
        /// Creates a dual-stack resolver fanning IPv4 next-hops to <paramref name="ipv4"/> (ARP) and IPv6 next-hops to
        /// <paramref name="ipv6"/> (NDISC).
        /// </summary>
        /// <param name="ipv4">The IPv4 (ARP) resolver — typically an <see cref="ArpResolver"/>.</param>
        /// <param name="ipv6">The IPv6 (NDISC) resolver — typically a <see cref="NdiscResolver"/>.</param>
        /// <param name="ownsInnerResolvers">
        /// When <c>true</c> (default), <see cref="DisposeAsync"/> disposes both inner resolvers (if they are
        /// <see cref="IAsyncDisposable"/>). Set <c>false</c> if the caller owns their lifetime.
        /// </param>
        public DualStackNeighborResolver(INeighborResolver ipv4, INeighborResolver ipv6, bool ownsInnerResolvers = true)
        {
            _ipv4 = ipv4 ?? throw new ArgumentNullException(nameof(ipv4));
            _ipv6 = ipv6 ?? throw new ArgumentNullException(nameof(ipv6));
            OwnsInnerResolvers = ownsInnerResolvers;
        }

        /// <summary>The IPv4 (ARP) resolver IPv4 next-hops are routed to.</summary>
        public INeighborResolver Ipv4 => _ipv4;

        /// <summary>The IPv6 (NDISC) resolver IPv6 next-hops are routed to.</summary>
        public INeighborResolver Ipv6 => _ipv6;

        /// <summary>Whether disposing this resolver also disposes the two inner resolvers.</summary>
        public bool OwnsInnerResolvers { get; }

        /// <inheritdoc/>
        public ValueTask<ReadOnlyMemory<byte>?> ResolveAsync(IPAddress nextHop, CancellationToken cancellationToken = default)
        {
            if (nextHop is null)
                return new ValueTask<ReadOnlyMemory<byte>?>((ReadOnlyMemory<byte>?)null);

            return nextHop.AddressFamily switch
            {
                AddressFamily.InterNetwork => _ipv4.ResolveAsync(nextHop, cancellationToken),
                AddressFamily.InterNetworkV6 => _ipv6.ResolveAsync(nextHop, cancellationToken),
                _ => new ValueTask<ReadOnlyMemory<byte>?>((ReadOnlyMemory<byte>?)null),   // neither ARP nor NDISC
            };
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;
            if (!OwnsInnerResolvers)
                return;
            if (_ipv4 is IAsyncDisposable v4)
                await v4.DisposeAsync().ConfigureAwait(false);
            if (_ipv6 is IAsyncDisposable v6)
                await v6.DisposeAsync().ConfigureAwait(false);
        }
    }
}
