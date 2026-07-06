using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Fou
{
    /// <summary>
    /// Creates the (not-yet-connected) UDP datagram pipe that carries a FOU/GUE tunnel's inner payload. A seam (instance
    /// behind an interface) so <see cref="FouConnection"/> can be unit-tested with a fake transport and no real socket —
    /// the default is <see cref="FouUdpTransportFactory"/>. Mirrors the GRE-in-UDP driver's <c>IGreUdpTransportFactory</c>:
    /// the returned transport is opened later by the connection via <see cref="IDatagramTransport.ConnectAsync"/>, and the
    /// GUE header (when in GUE mode) is added by the connection wrapping this transport in a <see cref="GueFramingTransport"/>.
    /// </summary>
    public interface IFouTransportFactory
    {
        /// <summary>Creates a UDP datagram transport targeting <paramref name="remote"/> (host:port). Not yet connected.</summary>
        IDatagramTransport Create(IPEndPoint remote);
    }
}
