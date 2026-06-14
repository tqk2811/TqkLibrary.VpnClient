using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Ikev2
{
    /// <summary>Adapts an <see cref="Ikev2Connection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class Ikev2VpnConnection : IVpnConnection
    {
        readonly Ikev2Connection _inner;
        readonly IVpnSession _session;

        /// <summary>Wraps a connected <see cref="Ikev2Connection"/> and its single session.</summary>
        public Ikev2VpnConnection(Ikev2Connection inner, IVpnSession session)
        {
            _inner = inner;
            _session = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => new[] { _session };

        /// <summary>
        /// IKEv2-native is strictly one CHILD_SA / one virtual IP in this driver — a second session would need a
        /// separate CREATE_CHILD_SA with its own traffic selectors, which is out of scope. Always throws.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("IKEv2-native carries a single CHILD_SA; additional sessions are not supported.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
