using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Fou
{
    /// <summary>
    /// The production <see cref="IFouTransportFactory"/>: hands out a real connected UDP socket
    /// (<see cref="FouUdpDatagramTransport"/>) to carry a FOU/GUE tunnel's inner payload. Needs no elevation and no raw IP
    /// socket — FOU/GUE ride an ordinary UDP datagram pipe.
    /// </summary>
    public sealed class FouUdpTransportFactory : IFouTransportFactory
    {
        readonly IPAddress? _localBind;

        /// <summary>Creates the factory. <paramref name="localBind"/> optionally pins the local source address (null → any).</summary>
        public FouUdpTransportFactory(IPAddress? localBind = null)
        {
            _localBind = localBind;
        }

        /// <inheritdoc/>
        public IDatagramTransport Create(IPEndPoint remote) => new FouUdpDatagramTransport(remote, _localBind);
    }
}
