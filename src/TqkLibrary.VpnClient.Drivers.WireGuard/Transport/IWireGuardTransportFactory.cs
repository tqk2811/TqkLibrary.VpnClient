using System.Net;

namespace TqkLibrary.VpnClient.Drivers.WireGuard.Transport
{
    /// <summary>
    /// Connects the UDP transport a WireGuard session rides — one datagram is one WireGuard message (type 1/2/3/4),
    /// so there is never any framing. The connection resolves the host then asks the factory for a transport to that
    /// endpoint; the production factory opens a real UDP socket, an in-process factory returns a loopback so the whole
    /// driver can be driven offline. Mirrors <c>IOpenVpnTransportFactory</c>.
    /// </summary>
    public interface IWireGuardTransportFactory
    {
        /// <summary>
        /// Connects a transport to <paramref name="remote"/> and returns it (with its inbound dispatch and the optional
        /// receive pump). The pump, when present, must be run by the caller on a task tied to the attempt lifetime.
        /// </summary>
        Task<WireGuardTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken);
    }
}
