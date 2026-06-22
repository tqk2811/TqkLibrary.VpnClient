using System.Net;
using System.Net.Sockets;
using System.Security;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Transport.RawIp.Exceptions;
using TqkLibrary.VpnClient.Transport.RawIp.Interfaces;

namespace TqkLibrary.VpnClient.Transport.RawIp
{
    /// <summary>
    /// Production <see cref="IRawIpTransportFactory"/>: opens real OS raw sockets (<see cref="SocketType.Raw"/>) to carry
    /// an arbitrary IP protocol (ESP proto-50, GRE proto-47, …) with no UDP/TCP wrapper. Requires elevation (Windows
    /// Administrator / Linux root or CAP_NET_RAW).
    /// <para><b>Windows caveat:</b> a raw socket may open yet still not receive a given protocol because the OS IPsec
    /// stack (IKEEXT/PolicyAgent) claims proto-50 or the firewall drops it inbound; treat Windows as best-effort and
    /// validate on Linux. <see cref="IsAvailable"/> proves only that a socket can be opened, not that the protocol is reachable.</para>
    /// </summary>
    public sealed class RawIpTransportFactory : IRawIpTransportFactory
    {
        readonly IPrivilegeChecker _privilegeChecker;
        readonly int _probeProtocol;

        /// <summary>
        /// Creates the factory. <paramref name="privilegeChecker"/> composes the error message (default heuristic);
        /// <paramref name="probeProtocol"/> is the IP protocol opened by <see cref="IsAvailable"/> to test the privilege (default ESP).
        /// </summary>
        public RawIpTransportFactory(IPrivilegeChecker? privilegeChecker = null, int probeProtocol = RawIpProtocols.Esp)
        {
            _privilegeChecker = privilegeChecker ?? new RawIpPrivilegeChecker();
            _probeProtocol = probeProtocol;
        }

        /// <inheritdoc/>
        public bool IsAvailable
        {
            get
            {
                try
                {
                    using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Raw, (ProtocolType)_probeProtocol);
                    return true;
                }
                catch (SocketException) { return false; }
                catch (SecurityException) { return false; }
                catch (UnauthorizedAccessException) { return false; }
            }
        }

        /// <inheritdoc/>
        public IDatagramTransport Create(IPAddress remote, int ipProtocol, IPAddress? localBind = null)
        {
            if (remote is null) throw new ArgumentNullException(nameof(remote));

            Socket socket;
            try
            {
                socket = new Socket(remote.AddressFamily, SocketType.Raw, (ProtocolType)ipProtocol);
            }
            catch (Exception ex) when (ex is SocketException or SecurityException or UnauthorizedAccessException)
            {
                throw new RawIpNotPermittedException(
                    $"Could not open a raw IP socket for protocol {ipProtocol}. A raw socket requires elevation"
                    + (_privilegeChecker.IsElevated
                        ? "; the process looks elevated, so the OS may be withholding the protocol (on Windows the IPsec service can claim proto-50 — check the firewall)."
                        : " (run as Administrator on Windows, or as root / with CAP_NET_RAW on Linux)."),
                    ex);
            }

            if (localBind != null)
            {
                try { socket.Bind(new IPEndPoint(localBind, 0)); }
                catch { socket.Dispose(); throw; }
            }

            return new RawIpDatagramTransport(socket, remote);
        }
    }
}
