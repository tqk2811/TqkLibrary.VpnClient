using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Ayiya
{
    /// <summary>
    /// The production <see cref="IAyiyaTransportFactory"/>: hands out a real connected UDP socket
    /// (<see cref="AyiyaUdpDatagramTransport"/>) to carry an AYIYA tunnel's signed payload. Needs no elevation and no raw
    /// IP socket — AYIYA rides an ordinary UDP datagram pipe.
    /// </summary>
    public sealed class AyiyaUdpTransportFactory : IAyiyaTransportFactory
    {
        readonly IPAddress? _localBind;

        /// <summary>Creates the factory. <paramref name="localBind"/> optionally pins the local source address (null → any).</summary>
        public AyiyaUdpTransportFactory(IPAddress? localBind = null)
        {
            _localBind = localBind;
        }

        /// <inheritdoc/>
        public IDatagramTransport Create(IPEndPoint remote) => new AyiyaUdpDatagramTransport(remote, _localBind);
    }
}
