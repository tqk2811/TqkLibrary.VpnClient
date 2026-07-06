using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.VpnClient.Drivers.Geneve.Transport
{
    /// <summary>
    /// Connects the UDP transport a Geneve endpoint rides to its remote peer — one datagram is one Geneve datagram (8-byte
    /// base header + optional options + payload), so there is never any framing. The connection resolves the remote
    /// endpoint then asks the factory for a transport to it; the production factory opens a real UDP socket, an in-process
    /// factory returns a loopback so the whole driver can be driven offline. Mirrors <c>IVxlanTransportFactory</c>.
    /// </summary>
    public interface IGeneveTransportFactory
    {
        /// <summary>
        /// Connects a transport to <paramref name="remote"/> (the remote Geneve endpoint) and returns it (with its inbound
        /// dispatch and the optional receive pump). The pump, when present, must be run by the caller on a task tied to the
        /// attempt lifetime.
        /// </summary>
        Task<GeneveTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken);
    }
}
