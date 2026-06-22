namespace TqkLibrary.VpnClient.Transport.RawIp.Interfaces
{
    /// <summary>
    /// Best-effort check for whether the current process looks elevated enough to open a raw socket. Used <b>only</b> to
    /// compose a helpful error message — the authoritative test is actually opening the socket
    /// (<see cref="RawIpTransportFactory.IsAvailable"/>), because elevation does not guarantee a protocol is reachable
    /// (a Linux process can hold CAP_NET_RAW without being root; Windows may still withhold inbound proto-50).
    /// </summary>
    public interface IPrivilegeChecker
    {
        /// <summary>True if the process appears to run as Administrator (Windows) or with euid 0 (Unix). Heuristic only.</summary>
        bool IsElevated { get; }
    }
}
