using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.GtpU
{
    /// <summary>
    /// The production <see cref="IGtpUTransportFactory"/>: hands out a real connected UDP socket
    /// (<see cref="GtpUUdpDatagramTransport"/>) to carry a GTP-U tunnel's inner payload. Needs no elevation and no raw IP
    /// socket — GTP-U rides an ordinary UDP datagram pipe (default port 2152).
    /// </summary>
    public sealed class GtpUUdpTransportFactory : IGtpUTransportFactory
    {
        readonly IPAddress? _localBind;

        /// <summary>Creates the factory. <paramref name="localBind"/> optionally pins the local source address (null → any).</summary>
        public GtpUUdpTransportFactory(IPAddress? localBind = null)
        {
            _localBind = localBind;
        }

        /// <inheritdoc/>
        public IDatagramTransport Create(IPEndPoint remote) => new GtpUUdpDatagramTransport(remote, _localBind);
    }
}
