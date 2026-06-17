using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Transport
{
    /// <summary>
    /// What an <see cref="IOpenConnectTransportFactory"/> hands back: the established (TLS-handshaked) byte stream the
    /// HTTP auth/CONNECT and the CSTP tunnel both ride. OpenConnect runs HTTP and then CSTP framing on the <i>same</i>
    /// reliable byte pipe, so — unlike the datagram drivers — there is no separate receive pump here: the connection
    /// reads the stream directly (request/response during auth, then a CSTP read loop). The stream is disposed when the
    /// attempt ends.
    /// </summary>
    public sealed class OpenConnectTransportHandle
    {
        /// <summary>Creates a handle around an established byte <paramref name="stream"/>.</summary>
        public OpenConnectTransportHandle(IByteStreamTransport stream)
            => Stream = stream ?? throw new ArgumentNullException(nameof(stream));

        /// <summary>The established TLS byte stream (HTTP auth/CONNECT + CSTP tunnel ride this).</summary>
        public IByteStreamTransport Stream { get; }
    }
}
