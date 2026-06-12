namespace TqkLibrary.Vpn.IpStack
{
    /// <summary>Thrown by <see cref="TcpIpStack.PingAsync"/> when the target replies with ICMP Destination Unreachable.</summary>
    public sealed class IcmpUnreachableException : Exception
    {
        /// <summary>Creates the exception carrying the ICMP Destination-Unreachable code.</summary>
        public IcmpUnreachableException(byte code)
            : base($"ICMP destination unreachable (code {code}).")
        {
            Code = code;
        }

        /// <summary>The ICMP Destination-Unreachable code (RFC 792 §3.1, e.g. 1 = host, 3 = port).</summary>
        public byte Code { get; }
    }
}
