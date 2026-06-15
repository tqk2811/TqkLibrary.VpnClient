using TqkLibrary.VpnClient.OpenVpn;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Transport
{
    /// <summary>
    /// What an <see cref="IOpenVpnTransportFactory"/> hands back: the packet transport the control/data channels ride,
    /// the optional receive-loop pump the connection must run (the UDP/TCP socket transports read on a background task;
    /// an in-process loopback delivers itself, so its pump is null), and the optional underlying socket to dispose when
    /// the attempt ends.
    /// </summary>
    public sealed class OpenVpnTransportHandle
    {
        /// <summary>Creates a handle around <paramref name="transport"/>.</summary>
        public OpenVpnTransportHandle(IOpenVpnTransport transport,
            Func<CancellationToken, Task>? receivePump = null, IAsyncDisposable? underlying = null)
        {
            Transport = transport ?? throw new ArgumentNullException(nameof(transport));
            ReceivePump = receivePump;
            Underlying = underlying;
        }

        /// <summary>The OpenVPN packet transport (control + data ride this).</summary>
        public IOpenVpnTransport Transport { get; }

        /// <summary>The receive loop to run on a background task once the handlers are wired; null for a self-pumping transport.</summary>
        public Func<CancellationToken, Task>? ReceivePump { get; }

        /// <summary>The underlying socket to dispose when the attempt is torn down; null when the factory owns nothing disposable.</summary>
        public IAsyncDisposable? Underlying { get; }
    }
}
