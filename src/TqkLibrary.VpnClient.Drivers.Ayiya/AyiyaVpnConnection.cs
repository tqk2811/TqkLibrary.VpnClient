using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Ayiya
{
    /// <summary>Adapts a <see cref="AyiyaConnection"/> to the <see cref="IVpnConnection"/> contract (a single L3 session).</summary>
    public sealed class AyiyaVpnConnection : IVpnConnection
    {
        readonly AyiyaConnection _inner;
        readonly IVpnSession[] _sessions;

        /// <summary>Wraps a connected <see cref="AyiyaConnection"/> and its single session.</summary>
        public AyiyaVpnConnection(AyiyaConnection inner, IVpnSession session)
        {
            _inner = inner;
            _sessions = new[] { session };
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => _sessions;

        /// <summary>
        /// An AYIYA tunnel is single-session (one encapsulation per remote); additional sessions are not supported.
        /// Always throws <see cref="NotSupportedException"/>.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("AYIYA supports a single session per connection.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
