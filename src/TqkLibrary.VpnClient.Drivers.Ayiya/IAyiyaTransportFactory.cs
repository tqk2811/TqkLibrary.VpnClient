using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Ayiya
{
    /// <summary>
    /// Creates the (not-yet-connected) UDP datagram pipe that carries an AYIYA tunnel's signed payload. A seam (instance
    /// behind an interface) so <see cref="AyiyaConnection"/> can be unit-tested with a fake transport and no real socket —
    /// the default is <see cref="AyiyaUdpTransportFactory"/>. Mirrors the FOU driver's <c>IFouTransportFactory</c>: the
    /// returned transport is opened later by the connection via <see cref="IDatagramTransport.ConnectAsync"/>, and the AYIYA
    /// header is added by the connection wrapping this transport in an <see cref="AyiyaFramingTransport"/>.
    /// </summary>
    public interface IAyiyaTransportFactory
    {
        /// <summary>Creates a UDP datagram transport targeting <paramref name="remote"/> (host:port). Not yet connected.</summary>
        IDatagramTransport Create(IPEndPoint remote);
    }
}
