using System.Collections.Generic;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn
{
    /// <summary>
    /// Adapts an <see cref="OpenVpnConnection"/> to the <see cref="IVpnConnection"/> contract. tun-mode and single-host
    /// tap-mode own exactly one session and reject <see cref="OpenSessionAsync"/>. Multi-host tap-mode bridges a whole L2
    /// broadcast domain (the tap channel is an uplink port on an in-memory switch): the primary station is the first
    /// session and <see cref="OpenSessionAsync"/> attaches another station (its own MAC/IP/channel) that leases over the
    /// shared switch.
    /// </summary>
    public sealed class OpenVpnVpnConnection : IVpnConnection
    {
        readonly OpenVpnConnection _inner;

        /// <summary>
        /// The supervised connection underneath, so a host holding the tunnel open can watch its
        /// <c>State</c>/<c>StateChanged</c> rather than invent a health check the driver already has.
        /// </summary>
        public OpenVpnConnection Connection => _inner;
        readonly IVpnSession _primary;
        readonly object _sync = new object();
        readonly List<IVpnSession> _extraSessions = new List<IVpnSession>();
        int _stationCounter;

        /// <summary>Wraps a connected <see cref="OpenVpnConnection"/> and its primary session.</summary>
        public OpenVpnVpnConnection(OpenVpnConnection inner, IVpnSession session)
        {
            _inner = inner;
            _primary = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions
        {
            get
            {
                lock (_sync)
                {
                    var all = new List<IVpnSession>(_extraSessions.Count + 1) { _primary };
                    all.AddRange(_extraSessions);
                    return all;
                }
            }
        }

        /// <summary>
        /// Opens an additional session. tun-mode / single-host tap carry one IP session, so this is rejected; in
        /// multi-host tap mode it attaches another station to the broadcast domain (a fresh locally-administered MAC, its
        /// own DHCP lease over the shared switch).
        /// </summary>
        public async Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
        {
            if (!_inner.IsMultiHost)
                throw new NotSupportedException("OpenVPN carries a single IP session here; construct the driver with multiHost: true and dev tap for an L2 broadcast domain.");

            MacAddress mac = NextStationMac();
            EthernetHostSession station = await _inner.AddStationAsync(mac, staticAddress: null, cancellationToken).ConfigureAwait(false);
            lock (_sync)
                _extraSessions.Add(station);
            return station;
        }

        // A locally-administered unicast MAC distinct from the primary's: U/L bit set, multicast bit clear, with a
        // per-connection counter in the low octets so each station is unique on the broadcast domain.
        MacAddress NextStationMac()
        {
            int n = System.Threading.Interlocked.Increment(ref _stationCounter);
            byte[] bytes = _inner.LinkAddress.ToArray();
            bytes[0] = (byte)((bytes[0] & 0xFE) | 0x02);
            bytes[4] = (byte)(n >> 8);
            bytes[5] = (byte)n;
            return MacAddress.FromBytes(bytes);
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            IVpnSession[] extras;
            lock (_sync)
            {
                extras = _extraSessions.ToArray();
                _extraSessions.Clear();
            }
            foreach (IVpnSession session in extras)
            {
                try { await session.DisposeAsync().ConfigureAwait(false); } catch { /* tear down the rest regardless */ }
            }
            await _inner.DisposeAsync().ConfigureAwait(false);
        }
    }
}
