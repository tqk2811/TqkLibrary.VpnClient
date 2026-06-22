using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.IpEncap
{
    /// <summary>Adapts an <see cref="IpEncapConnection"/> to the <see cref="IVpnConnection"/> contract (a single L3 session).</summary>
    public sealed class IpEncapVpnConnection : IVpnConnection
    {
        readonly IpEncapConnection _inner;
        readonly IVpnSession[] _sessions;

        /// <summary>Wraps a connected <see cref="IpEncapConnection"/> and its single session.</summary>
        public IpEncapVpnConnection(IpEncapConnection inner, IVpnSession session)
        {
            _inner = inner;
            _sessions = new[] { session };
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => _sessions;

        /// <summary>
        /// A plain IP-in-IP / GRE tunnel is single-session (one encapsulation per remote); additional sessions are not
        /// supported. Always throws <see cref="NotSupportedException"/>.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("Plain IP-encapsulation supports a single session per connection.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
