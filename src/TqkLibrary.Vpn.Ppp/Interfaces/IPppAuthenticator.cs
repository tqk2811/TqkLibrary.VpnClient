using TqkLibrary.Vpn.Ppp.Enums;

namespace TqkLibrary.Vpn.Ppp.Interfaces
{
    /// <summary>
    /// Drives a PPP authentication protocol (e.g. CHAP/MS-CHAPv2). The engine feeds each inbound auth packet
    /// here; the authenticator optionally returns a packet to send back and reports the overall status.
    /// </summary>
    public interface IPppAuthenticator
    {
        /// <summary>The PPP protocol number this authenticator handles (e.g. 0xC223 for CHAP).</summary>
        ushort Protocol { get; }

        /// <summary>
        /// Processes one inbound auth packet. Sets <paramref name="response"/> to a packet to send back
        /// (or null) and returns whether authentication is pending, succeeded, or failed.
        /// </summary>
        PppAuthStatus Handle(ReadOnlySpan<byte> packet, out byte[]? response);
    }
}
