using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Ethernet.Models;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// A multi-host L2 session over an <see cref="EthernetAdapter"/>: the as-built realization of
    /// <see cref="MultiHostModel.L2BroadcastDomain"/> — N <see cref="VirtualHost"/>s, each "one machine on the LAN",
    /// surfaced as N independent <see cref="EthernetHostSession"/> (<see cref="Abstractions.Drivers.Interfaces.IVpnSession"/>)
    /// sharing one in-memory switch fabric. This is the assembly layer an L2 driver (SoftEther, OpenVPN-tap) uses to
    /// expose a whole broadcast domain instead of hand-bridging a single host down to L3.
    /// <para>
    /// The session matches a driver whose <c>Capabilities.LinkLayer == VpnLinkLayer.L2Ethernet</c> and
    /// <c>MultiHostModel == MultiHostModel.L2BroadcastDomain</c>: <see cref="AddStationAsync"/> attaches a station
    /// (running its DHCP/SLAAC configurator to obtain a lease), and <see cref="Sessions"/> enumerates the live stations.
    /// </para>
    /// </summary>
    public sealed class MultiHostSession : IAsyncDisposable
    {
        readonly EthernetAdapter _adapter;
        readonly bool _ownsAdapter;
        readonly object _sync = new object();
        readonly Dictionary<MacAddress, EthernetHostSession> _sessions = new Dictionary<MacAddress, EthernetHostSession>();
        bool _disposed;

        /// <summary>
        /// Creates a multi-host session over <paramref name="adapter"/>. When <paramref name="ownsAdapter"/> is
        /// <c>true</c> (default) <see cref="DisposeAsync"/> disposes the adapter (and through it the switch + every host);
        /// otherwise the caller owns the adapter's lifetime.
        /// </summary>
        public MultiHostSession(EthernetAdapter adapter, bool ownsAdapter = true)
        {
            _adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
            _ownsAdapter = ownsAdapter;
        }

        /// <summary>This session's link layer (always <see cref="VpnLinkLayer.L2Ethernet"/>).</summary>
        public VpnLinkLayer LinkLayer => VpnLinkLayer.L2Ethernet;

        /// <summary>This session's multi-host model (always <see cref="MultiHostModel.L2BroadcastDomain"/>).</summary>
        public MultiHostModel MultiHostModel => MultiHostModel.L2BroadcastDomain;

        /// <summary>The underlying adapter (switch + hosts) — exposed so a driver can attach its own uplink port.</summary>
        public EthernetAdapter Adapter => _adapter;

        /// <summary>Number of stations currently attached.</summary>
        public int StationCount
        {
            get { lock (_sync) return _sessions.Count; }
        }

        /// <summary>A snapshot of the live stations, each an <see cref="EthernetHostSession"/>.</summary>
        public IReadOnlyList<EthernetHostSession> Sessions
        {
            get { lock (_sync) return new List<EthernetHostSession>(_sessions.Values); }
        }

        /// <summary>Returns the station with <paramref name="mac"/>, or <c>null</c> if none is attached.</summary>
        public EthernetHostSession? GetStation(MacAddress mac)
        {
            lock (_sync)
                return _sessions.TryGetValue(mac, out EthernetHostSession? session) ? session : null;
        }

        /// <summary>
        /// Attaches a station with MAC <paramref name="mac"/> built by <paramref name="build"/> (the same callback shape
        /// as <see cref="EthernetAdapter.AddHost"/>) and carrying the supplied <paramref name="config"/> (e.g. an
        /// ifconfig push). The station's host handle is owned by the session, so it is torn down on
        /// <see cref="RemoveStationAsync"/> / <see cref="DisposeAsync"/>.
        /// </summary>
        public EthernetHostSession AddStation(MacAddress mac, Func<IEthernetChannel, EthernetHostSpec> build, TunnelConfig config)
        {
            if (config is null) throw new ArgumentNullException(nameof(config));
            EthernetAdapter.EthernetHostHandle handle = _adapter.AddHost(mac, build);
            return Register(mac, new EthernetHostSession(handle, config, ownsHandle: false));
        }

        /// <summary>
        /// Attaches a station with MAC <paramref name="mac"/> and immediately runs its <see cref="IAddressConfigurator"/>
        /// (DHCPv4 / SLAAC+DHCPv6) to obtain a lease — the multi-host equivalent of a single host's DHCP bind. The
        /// station's <see cref="EthernetHostSpec"/> must carry a <see cref="EthernetHostSpec.Configurator"/>.
        /// </summary>
        /// <exception cref="InvalidOperationException">The built host has no configurator.</exception>
        public async ValueTask<EthernetHostSession> AddStationAsync(MacAddress mac, Func<IEthernetChannel, EthernetHostSpec> build, CancellationToken cancellationToken = default)
        {
            EthernetAdapter.EthernetHostHandle handle = _adapter.AddHost(mac, build);
            try
            {
                TunnelConfig config = await handle.ConfigureAsync(cancellationToken).ConfigureAwait(false);
                return Register(mac, new EthernetHostSession(handle, config, ownsHandle: false));
            }
            catch
            {
                await _adapter.RemoveHostAsync(mac).ConfigureAwait(false);
                throw;
            }
        }

        EthernetHostSession Register(MacAddress mac, EthernetHostSession session)
        {
            lock (_sync)
            {
                if (_disposed)
                {
                    _ = _adapter.RemoveHostAsync(mac);
                    throw new ObjectDisposedException(nameof(MultiHostSession));
                }
                _sessions[mac] = session;
            }
            return session;
        }

        /// <summary>Detaches and disposes the station with <paramref name="mac"/> (no-op if none). Returns <c>true</c> if one was removed.</summary>
        public async ValueTask<bool> RemoveStationAsync(MacAddress mac)
        {
            lock (_sync)
            {
                if (!_sessions.Remove(mac))
                    return false;
            }
            // The session does not own its handle, so detach the host through the adapter (which disposes the handle).
            return await _adapter.RemoveHostAsync(mac).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            lock (_sync)
            {
                if (_disposed) return;
                _disposed = true;
                _sessions.Clear();
            }
            // The host handles are owned by the adapter (sessions were created with ownsHandle:false); disposing the
            // adapter tears down every host + the switch when this session owns the adapter.
            if (_ownsAdapter)
                await _adapter.DisposeAsync().ConfigureAwait(false);
        }
    }
}
