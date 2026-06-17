using System;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Ethernet.Models;

namespace TqkLibrary.VpnClient.Ethernet
{
    public sealed partial class EthernetAdapter
    {
        /// <summary>
        /// One virtual host attached to an <see cref="EthernetAdapter"/>: bundles the <see cref="VirtualHost"/> L2↔L3
        /// bridge, its <see cref="INeighborResolver"/> + optional <see cref="IAddressConfigurator"/>, and the
        /// backpressured <see cref="IPacketChannel"/> the host's userspace IP stack binds to. Disposing the handle tears
        /// the host down: it unwires the seams, disposes the channel (which detaches the switch port and stops the pump),
        /// and disposes the resolver/configurator when <see cref="EthernetHostSpec.OwnsResolverAndConfigurator"/> is set.
        /// </summary>
        public sealed class EthernetHostHandle : IAsyncDisposable
        {
            readonly MacAddress _mac;
            readonly VirtualHost _host;
            readonly BackpressuredPacketChannel _channel;
            readonly EthernetHostSpec _spec;
            int _disposed;

            internal EthernetHostHandle(MacAddress mac, VirtualHost host, BackpressuredPacketChannel channel, EthernetHostSpec spec)
            {
                _mac = mac;
                _host = host;
                _channel = channel;
                _spec = spec;
            }

            /// <summary>This host's MAC address.</summary>
            public MacAddress Mac => _mac;

            /// <summary>
            /// The backpressured L3 channel the host's userspace TCP/IP stack binds to (<c>new TcpIpStack(handle.Channel, ip)</c>).
            /// Inbound IP packets are pumped off the switch deliver path through a bounded queue (design 09).
            /// </summary>
            public IPacketChannel Channel => _channel;

            /// <summary>The neighbor resolver (ARP/NDISC) backing this host's egress.</summary>
            public INeighborResolver Resolver => _spec.Resolver;

            /// <summary>The address configurator (DHCPv4 / SLAAC+DHCPv6), or <c>null</c> if the host has none.</summary>
            public IAddressConfigurator? Configurator => _spec.Configurator;

            /// <summary>
            /// Runs this host's <see cref="IAddressConfigurator"/> (DHCP/SLAAC) to acquire its <see cref="TunnelConfig"/>.
            /// </summary>
            /// <exception cref="InvalidOperationException">The host was created without a configurator.</exception>
            public ValueTask<TunnelConfig> ConfigureAsync(CancellationToken cancellationToken = default)
            {
                if (_spec.Configurator is null)
                    throw new InvalidOperationException($"Host {_mac} has no IAddressConfigurator to run.");
                return _spec.Configurator.ConfigureAsync(cancellationToken);
            }

            /// <inheritdoc/>
            public async ValueTask DisposeAsync()
            {
                if (Interlocked.Exchange(ref _disposed, 1) != 0)
                    return;

                // Unwire the seams first so no inbound frame is dispatched into a half-disposed resolver/configurator.
                if (_spec.NonIpFrameHandler != null)
                    _host.InboundNonIpFrame -= _spec.NonIpFrameHandler;
                if (_spec.IpPacketHandler != null)
                    _host.InboundIpPacket -= _spec.IpPacketHandler;

                // Disposing the channel disposes the VirtualHost (detaches + disposes the switch port) and stops the pump.
                await _channel.DisposeAsync().ConfigureAwait(false);

                if (_spec.OwnsResolverAndConfigurator)
                {
                    if (_spec.Configurator is IAsyncDisposable configurator)
                        await configurator.DisposeAsync().ConfigureAwait(false);
                    if (_spec.Resolver is IAsyncDisposable resolver)
                        await resolver.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
    }
}
