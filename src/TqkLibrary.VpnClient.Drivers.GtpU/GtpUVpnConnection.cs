using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.GtpU
{
    /// <summary>Adapts a <see cref="GtpUConnection"/> to the <see cref="IVpnConnection"/> contract (a single L3 session).</summary>
    public sealed class GtpUVpnConnection : IVpnConnection
    {
        readonly GtpUConnection _inner;
        readonly IVpnSession[] _sessions;

        /// <summary>Wraps a connected <see cref="GtpUConnection"/> and its single session.</summary>
        public GtpUVpnConnection(GtpUConnection inner, IVpnSession session)
        {
            _inner = inner;
            _sessions = new[] { session };
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => _sessions;

        /// <summary>
        /// A GTP-U tunnel is single-session (one TEID per remote); additional sessions are not supported.
        /// Always throws <see cref="NotSupportedException"/>.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("GTP-U supports a single session per connection.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
