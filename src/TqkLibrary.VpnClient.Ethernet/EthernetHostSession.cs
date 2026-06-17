using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// One LAN station of a multi-host L2 broadcast domain, surfaced as an <see cref="IVpnSession"/>: it adapts a single
    /// <see cref="EthernetAdapter.EthernetHostHandle"/> (a <see cref="VirtualHost"/> + its resolver/configurator on the
    /// in-memory switch) to the abstraction-level session contract. Each virtual host is "one machine on the LAN" — its
    /// own MAC/IP, its own <see cref="IPacketChannel"/>, its own <see cref="TunnelConfig"/> — exactly the per-host
    /// session an L2 driver (SoftEther, OpenVPN-tap) advertises through <c>MultiHostModel.L2BroadcastDomain</c>.
    /// <para>
    /// <see cref="PacketChannel"/> is the handle's backpressured L3 channel (the stable façade a userspace IP stack binds
    /// to). <see cref="Config"/> is the configuration the station obtained — either supplied at construction (an ifconfig
    /// push) or built from the host's <see cref="EthernetAdapter.EthernetHostHandle.ConfigureAsync"/> DHCP/SLAAC lease.
    /// </para>
    /// </summary>
    public sealed class EthernetHostSession : IVpnSession
    {
        readonly EthernetAdapter.EthernetHostHandle _handle;
        readonly bool _ownsHandle;

        /// <summary>
        /// Wraps <paramref name="handle"/> as a session carrying <paramref name="config"/>. When
        /// <paramref name="ownsHandle"/> is <c>true</c> (default) disposing the session disposes the host handle (which
        /// detaches its switch port and disposes its owned resolver/configurator); otherwise the caller owns the handle —
        /// use that when the host lives on a <see cref="MultiHostSession"/> that owns the adapter.
        /// </summary>
        public EthernetHostSession(EthernetAdapter.EthernetHostHandle handle, TunnelConfig config, bool ownsHandle = true)
        {
            _handle = handle ?? throw new System.ArgumentNullException(nameof(handle));
            Config = config ?? throw new System.ArgumentNullException(nameof(config));
            _ownsHandle = ownsHandle;
        }

        /// <summary>Runs the host's <see cref="IAddressConfigurator"/> (DHCPv4 / SLAAC+DHCPv6) and wraps the lease as a session.</summary>
        /// <exception cref="System.InvalidOperationException">The host was attached without a configurator.</exception>
        public static async ValueTask<EthernetHostSession> ConfigureAsync(EthernetAdapter.EthernetHostHandle handle, bool ownsHandle = true, System.Threading.CancellationToken cancellationToken = default)
        {
            if (handle is null) throw new System.ArgumentNullException(nameof(handle));
            TunnelConfig config = await handle.ConfigureAsync(cancellationToken).ConfigureAwait(false);
            return new EthernetHostSession(handle, config, ownsHandle);
        }

        /// <summary>This station's MAC address on the broadcast domain.</summary>
        public MacAddress Mac => _handle.Mac;

        /// <summary>The underlying virtual-host handle (resolver/configurator/channel).</summary>
        public EthernetAdapter.EthernetHostHandle Handle => _handle;

        /// <inheritdoc/>
        public TunnelConfig Config { get; }

        /// <inheritdoc/>
        public IPacketChannel PacketChannel => _handle.Channel;

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _ownsHandle ? _handle.DisposeAsync() : default;
    }
}
