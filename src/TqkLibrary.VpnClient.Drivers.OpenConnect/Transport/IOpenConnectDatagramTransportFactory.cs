using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Transport
{
    /// <summary>
    /// Connects the <b>plaintext UDP</b> datagram pipe the OpenConnect DTLS data path rides. After the HTTP CONNECT
    /// response advertises the <c>X-DTLS-*</c> headers, the connection asks this factory for a raw UDP transport to the
    /// gateway's DTLS port; it then wraps that transport in a <c>DtlsDatagramTransport</c> (roadmap F.3) and runs the
    /// DTLS 1.2 handshake, finally framing CSTP packets over it (one datagram = one packet). The production factory
    /// opens a real connected UDP socket; an in-process factory returns a loopback so the whole DTLS path can be driven
    /// offline. Mirrors the byte-stream <see cref="IOpenConnectTransportFactory"/>. When no datagram factory is supplied
    /// the connection stays on the TLS data path (fallback).
    /// </summary>
    public interface IOpenConnectDatagramTransportFactory
    {
        /// <summary>
        /// Connects a UDP datagram pipe to <paramref name="remote"/> (the gateway's DTLS endpoint) for the given
        /// <paramref name="host"/> and returns it. The returned transport is the <b>plaintext</b> UDP pipe — the
        /// connection layers DTLS on top.
        /// </summary>
        Task<IDatagramTransport> ConnectAsync(string host, IPEndPoint remote, CancellationToken cancellationToken);
    }
}
