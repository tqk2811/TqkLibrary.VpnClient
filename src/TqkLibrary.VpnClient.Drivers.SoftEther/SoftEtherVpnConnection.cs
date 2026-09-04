using System.Collections.Generic;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Drivers.SoftEther
{
    /// <summary>
    /// Adapts a <see cref="SoftEtherConnection"/> to the <see cref="IVpnConnection"/> contract. In single-host mode it
    /// owns exactly one session and rejects <see cref="OpenSessionAsync"/>. In multi-host mode the data channel is an
    /// uplink port on an in-memory switch (a whole L2 broadcast domain): the primary station is the first session and
    /// <see cref="OpenSessionAsync"/> attaches another station (its own MAC/IP/channel) that the SecureNAT server leases
    /// over the shared switch.
    /// </summary>
    public sealed class SoftEtherVpnConnection : IVpnConnection
    {
        readonly SoftEtherConnection _inner;

        /// <summary>
        /// The supervised connection underneath, so a host holding the tunnel open can watch its
        /// <c>State</c>/<c>StateChanged</c> rather than invent a health check the driver already has.
        /// </summary>
        public SoftEtherConnection Connection => _inner;
        readonly IVpnSession _primary;
        readonly object _sync = new object();
        readonly List<IVpnSession> _extraSessions = new List<IVpnSession>();
        int _stationCounter;

        /// <summary>Wraps a connected <see cref="SoftEtherConnection"/> and its primary session.</summary>
        public SoftEtherVpnConnection(SoftEtherConnection inner, IVpnSession session)
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
        /// Opens an additional session. Single-host SoftEther bridges one L2 host down to one L3 session, so this is
        /// rejected; in multi-host mode it attaches another station to the broadcast domain (a fresh locally-administered
        /// MAC, its own DHCP lease over the shared switch).
        /// </summary>
        public async Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
        {
            if (!_inner.IsMultiHost)
                throw new NotSupportedException("The SoftEther driver bridges a single L2 host to one IP session; construct the driver with multiHost: true for an L2 broadcast domain.");

            MacAddress mac = NextStationMac();
            EthernetHostSession station = await _inner.AddStationAsync(mac, cancellationToken).ConfigureAwait(false);
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
