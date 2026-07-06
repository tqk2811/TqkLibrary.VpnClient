using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Fou
{
    /// <summary>Adapts a <see cref="FouConnection"/> to the <see cref="IVpnConnection"/> contract (a single L3 session).</summary>
    public sealed class FouVpnConnection : IVpnConnection
    {
        readonly FouConnection _inner;
        readonly IVpnSession[] _sessions;

        /// <summary>Wraps a connected <see cref="FouConnection"/> and its single session.</summary>
        public FouVpnConnection(FouConnection inner, IVpnSession session)
        {
            _inner = inner;
            _sessions = new[] { session };
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => _sessions;

        /// <summary>
        /// A FOU/GUE tunnel is single-session (one encapsulation per remote); additional sessions are not supported.
        /// Always throws <see cref="NotSupportedException"/>.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("FOU/GUE supports a single session per connection.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
