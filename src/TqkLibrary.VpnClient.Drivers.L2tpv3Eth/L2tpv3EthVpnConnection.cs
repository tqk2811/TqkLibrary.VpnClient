using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.L2tpv3Eth
{
    /// <summary>Adapts an <see cref="L2tpv3EthConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class L2tpv3EthVpnConnection : IVpnConnection
    {
        readonly L2tpv3EthConnection _inner;
        readonly IVpnSession _session;

        /// <summary>Wraps a connected <see cref="L2tpv3EthConnection"/> and its single session.</summary>
        public L2tpv3EthVpnConnection(L2tpv3EthConnection inner, IVpnSession session)
        {
            _inner = inner;
            _session = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => new[] { _session };

        /// <summary>
        /// An L2TPv3 static pseudowire carries a single point-to-point overlay L2 session per connection; a second session has
        /// no protocol meaning here. Always throws.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new System.NotSupportedException("L2TPv3 static pseudowire carries a single overlay L2 session; additional sessions are not supported.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
