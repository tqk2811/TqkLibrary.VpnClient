using System.Net;

namespace TqkLibrary.VpnClient.Abstractions.Transport.Interfaces
{
    /// <summary>
    /// Creates a raw-IP <see cref="IDatagramTransport"/> that carries an arbitrary IP protocol number (ESP proto-50,
    /// GRE proto-47, …) directly on IP, with no UDP/TCP wrapper. This is the only userspace path for a custom IP
    /// protocol and requires elevation (Windows Administrator / Linux root or CAP_NET_RAW), so it is an opt-in seam:
    /// drivers depend on this interface and stay no-admin by default; the concrete factory lives in
    /// <c>TqkLibrary.VpnClient.Transport.RawIp</c>.
    /// </summary>
    public interface IRawIpTransportFactory
    {
        /// <summary>
        /// True if a raw socket can actually be opened in this process (a real privilege probe, not a guess). Note that
        /// even when true, an OS may still withhold a specific inbound protocol (on Windows the IPsec service can claim
        /// proto-50 and the firewall can drop it), so this proves "permitted to open", not "protocol reachable".
        /// </summary>
        bool IsAvailable { get; }

        /// <summary>
        /// Opens a raw datagram transport toward <paramref name="remote"/> for the given IANA <paramref name="ipProtocol"/>.
        /// When <paramref name="localBind"/> is supplied the socket binds that source address (used to keep the native-ESP
        /// source identical to the address IKE authenticated on). Throws when the socket cannot be opened (e.g. no elevation).
        /// </summary>
        IDatagramTransport Create(IPAddress remote, int ipProtocol, IPAddress? localBind = null);
    }
}
