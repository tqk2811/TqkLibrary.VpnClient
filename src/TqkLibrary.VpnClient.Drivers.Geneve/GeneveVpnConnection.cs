using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Geneve
{
    /// <summary>Adapts a <see cref="GeneveConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class GeneveVpnConnection : IVpnConnection
    {
        readonly GeneveConnection _inner;
        readonly IVpnSession _session;

        /// <summary>Wraps a connected <see cref="GeneveConnection"/> and its single session.</summary>
        public GeneveVpnConnection(GeneveConnection inner, IVpnSession session)
        {
            _inner = inner;
            _session = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => new[] { _session };

        /// <summary>
        /// Geneve carries a single point-to-point overlay L2 session per connection; a second session has no protocol
        /// meaning here. Always throws.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new System.NotSupportedException("Geneve carries a single overlay L2 session; additional sessions are not supported.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
