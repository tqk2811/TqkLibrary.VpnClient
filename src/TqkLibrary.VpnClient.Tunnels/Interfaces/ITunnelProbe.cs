namespace TqkLibrary.VpnClient.Tunnels.Interfaces
{
    /// <summary>
    /// One question put THROUGH a tunnel: send something real, wait for anything to come back.
    /// </summary>
    /// <remarks>
    /// The point of the interface is that the answer must not come from the transport underneath.
    /// Asking a socket whether it is open, or a keepalive whether it was answered, tells you about
    /// the control plane; a server that has dropped the session's data plane keeps answering both.
    /// </remarks>
    public interface ITunnelProbe
    {
        /// <summary>
        /// True when something came back through the tunnel. False means silence, which is what a
        /// dead data plane looks like — never throw for it; the caller counts silences.
        /// </summary>
        Task<bool> IsAliveAsync(CancellationToken cancellationToken);
    }
}
