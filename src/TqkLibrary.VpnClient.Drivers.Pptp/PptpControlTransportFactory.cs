using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Pptp
{
    /// <summary>
    /// The seam that opens the PPTP control-connection byte stream for an endpoint. The default builds a real
    /// <see cref="Transport.PptpControlTcpTransport"/> over TCP/1723; tests inject an in-memory
    /// <see cref="IByteStreamTransport"/> so the driver can be driven against a simulated PAC without real sockets
    /// (mirroring how the data plane receives an <see cref="Abstractions.Transport.Interfaces.IRawIpTransportFactory"/>).
    /// The returned transport must already be connected (the factory awaits any connect).
    /// </summary>
    public delegate Task<IByteStreamTransport> PptpControlTransportFactory(VpnEndpoint endpoint, CancellationToken cancellationToken);
}
