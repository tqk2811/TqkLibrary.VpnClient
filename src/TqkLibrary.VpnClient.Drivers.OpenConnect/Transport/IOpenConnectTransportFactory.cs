using System.Net;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Transport
{
    /// <summary>
    /// Connects the TLS byte stream an OpenConnect session rides — OpenConnect runs HTTPS auth, an HTTP CONNECT and then
    /// CSTP framing all on the one reliable TLS pipe. The connection resolves the host then asks the factory for a
    /// stream to that endpoint; the production factory opens a real TCP socket and completes the TLS handshake, an
    /// in-process factory returns a loopback so the whole driver can be driven offline. Mirrors
    /// <c>IWireGuardTransportFactory</c> / <c>IOpenVpnTransportFactory</c> (byte-stream variant).
    /// </summary>
    public interface IOpenConnectTransportFactory
    {
        /// <summary>
        /// Connects (and TLS-handshakes) a byte stream to <paramref name="remote"/> for the given <paramref name="host"/>
        /// (the SNI / <c>Host:</c> value) and returns it. The returned stream is already connected — the caller starts
        /// the HTTP exchange immediately.
        /// </summary>
        Task<OpenConnectTransportHandle> ConnectAsync(string host, IPEndPoint remote, CancellationToken cancellationToken);
    }
}
