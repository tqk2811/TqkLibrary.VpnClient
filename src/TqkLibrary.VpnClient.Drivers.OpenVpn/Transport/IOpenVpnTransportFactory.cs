using System.Net;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Transport
{
    /// <summary>
    /// Connects the outer transport an OpenVPN session rides — UDP (one datagram = one packet) or TCP (16-bit length
    /// framing). The connection resolves the host then asks the factory for a transport to that endpoint; the production
    /// factory opens a real socket, an in-process factory returns a loopback so the whole driver can be driven offline.
    /// </summary>
    public interface IOpenVpnTransportFactory
    {
        /// <summary>
        /// Connects a transport to <paramref name="remote"/> and returns it (with its receive pump and the disposable
        /// socket). The pump, when present, must be run by the caller on a task tied to the attempt lifetime.
        /// </summary>
        Task<OpenVpnTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken);
    }
}
