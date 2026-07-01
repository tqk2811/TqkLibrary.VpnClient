using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.VpnClient.Drivers.Vxlan.Transport
{
    /// <summary>
    /// Connects the UDP transport a VXLAN endpoint rides to its remote VTEP — one datagram is one VXLAN datagram (8-byte
    /// header + Ethernet frame), so there is never any framing. The connection resolves the remote VTEP endpoint then
    /// asks the factory for a transport to it; the production factory opens a real UDP socket, an in-process factory
    /// returns a loopback so the whole driver can be driven offline. Mirrors <c>IN2nTransportFactory</c>.
    /// </summary>
    public interface IVxlanTransportFactory
    {
        /// <summary>
        /// Connects a transport to <paramref name="remote"/> (the remote VTEP) and returns it (with its inbound dispatch
        /// and the optional receive pump). The pump, when present, must be run by the caller on a task tied to the
        /// attempt lifetime.
        /// </summary>
        Task<VxlanTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken);
    }
}
