using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.GtpU
{
    /// <summary>
    /// Creates the (not-yet-connected) UDP datagram pipe that carries a GTP-U tunnel's inner payload. A seam (instance
    /// behind an interface) so <see cref="GtpUConnection"/> can be unit-tested with a fake transport and no real socket —
    /// the default is <see cref="GtpUUdpTransportFactory"/>. Mirrors the FOU/AYIYA drivers' transport factory: the returned
    /// transport is opened later by the connection via <see cref="IDatagramTransport.ConnectAsync"/>, and the GTP-U header
    /// is added by the connection wrapping this transport in a <see cref="GtpUFramingTransport"/>.
    /// </summary>
    public interface IGtpUTransportFactory
    {
        /// <summary>Creates a UDP datagram transport targeting <paramref name="remote"/> (host:port). Not yet connected.</summary>
        IDatagramTransport Create(IPEndPoint remote);
    }
}
