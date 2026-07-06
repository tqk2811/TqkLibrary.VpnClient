using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.VpnClient.Drivers.VxlanGpe.Transport
{
    /// <summary>
    /// Connects the UDP transport a VXLAN-GPE endpoint rides to its remote peer — one datagram is one VXLAN-GPE datagram
    /// (8-byte header + payload), so there is never any framing. The connection resolves the remote endpoint then asks the
    /// factory for a transport to it; the production factory opens a real UDP socket, an in-process factory returns a
    /// loopback so the whole driver can be driven offline. Mirrors <c>IVxlanTransportFactory</c>.
    /// </summary>
    public interface IVxlanGpeTransportFactory
    {
        /// <summary>
        /// Connects a transport to <paramref name="remote"/> (the remote peer) and returns it (with its inbound dispatch and
        /// the optional receive pump). The pump, when present, must be run by the caller on a task tied to the attempt
        /// lifetime.
        /// </summary>
        Task<VxlanGpeTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken);
    }
}
