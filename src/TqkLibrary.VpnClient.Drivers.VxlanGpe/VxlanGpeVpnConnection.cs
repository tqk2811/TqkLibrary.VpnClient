using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.VxlanGpe
{
    /// <summary>Adapts a <see cref="VxlanGpeConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class VxlanGpeVpnConnection : IVpnConnection
    {
        readonly VxlanGpeConnection _inner;
        readonly IVpnSession _session;

        /// <summary>Wraps a connected <see cref="VxlanGpeConnection"/> and its single session.</summary>
        public VxlanGpeVpnConnection(VxlanGpeConnection inner, IVpnSession session)
        {
            _inner = inner;
            _session = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => new[] { _session };

        /// <summary>
        /// VXLAN-GPE carries a single point-to-point overlay L2 session per connection; a second session has no protocol
        /// meaning here. Always throws.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new System.NotSupportedException("VXLAN-GPE carries a single overlay L2 session; additional sessions are not supported.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
