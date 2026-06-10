using System.Net;

namespace TqkLibrary.Vpn.IpStack
{
    /// <summary>The outcome of a successful <see cref="Tcp.TcpIpStack.PingAsync"/>: round-trip time, echoed data and responder.</summary>
    public readonly struct PingReply
    {
        /// <summary>Creates a reply.</summary>
        public PingReply(IPAddress remoteAddress, TimeSpan roundTripTime, byte[] data)
        {
            RemoteAddress = remoteAddress;
            RoundTripTime = roundTripTime;
            Data = data;
        }

        /// <summary>The address that answered the echo.</summary>
        public IPAddress RemoteAddress { get; }

        /// <summary>Time between sending the Echo Request and receiving the matching Echo Reply.</summary>
        public TimeSpan RoundTripTime { get; }

        /// <summary>The echoed payload bytes returned by the responder.</summary>
        public byte[] Data { get; }
    }
}
