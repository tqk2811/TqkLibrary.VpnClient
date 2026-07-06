using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Transport
{
    /// <summary>
    /// Connects the UDP transport an L2TPv3 Ethernet-pseudowire endpoint rides to its remote peer — one datagram is one
    /// L2TPv3 data message (Session ID + optional Cookie + optional Default L2-Specific Sublayer + Ethernet frame), so there
    /// is never any framing. The connection resolves the remote endpoint then asks the factory for a transport to it; the
    /// production factory opens a real UDP socket, an in-process factory returns a loopback so the whole driver can be driven
    /// offline. Mirrors <c>IGeneveTransportFactory</c>.
    /// </summary>
    public interface IL2tpv3EthTransportFactory
    {
        /// <summary>
        /// Connects a transport to <paramref name="remote"/> (the remote L2TPv3 endpoint) and returns it (with its inbound
        /// dispatch and the optional receive pump). The pump, when present, must be run by the caller on a task tied to the
        /// attempt lifetime.
        /// </summary>
        Task<L2tpv3EthTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken);
    }
}
