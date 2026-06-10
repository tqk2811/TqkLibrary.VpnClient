namespace TqkLibrary.Vpn.IpStack.Tcp.Enums
{
    /// <summary>TCP connection states relevant to an active-open client (RFC 793, subset incl. the half-close FSM).</summary>
    public enum TcpState
    {
        Closed,
        SynSent,
        Established,
        FinWait1,
        FinWait2,
        Closing,
        TimeWait,
        CloseWait,
        LastAck,
    }
}
