using System.Text;

namespace TqkLibrary.VpnClient.SoftEther.DataChannel
{
    /// <summary>
    /// Constants for the SoftEther SSL-VPN data session — the phase that follows the control handshake once the server
    /// has returned the <c>welcome</c> PACK. From then on the same TLS byte stream stops carrying HTTP/PACK messages and
    /// instead carries length-prefixed batches of raw Ethernet frames ("Ethernet over HTTPS"). Re-implemented from the
    /// protocol behavior (spec doc <c>07</c>) — not copied from the GPL source.
    /// </summary>
    public static class SoftEtherDataConstants
    {
        /// <summary>
        /// The fixed ASCII keep-alive payload a SoftEther peer sends as a standalone data frame when the link is idle.
        /// The receiver recognises and drops it (it is not an Ethernet frame).
        /// </summary>
        public const string KeepAliveText = "Internet Connection Keep Alive Packet";

        /// <summary>The <see cref="KeepAliveText"/> as ASCII bytes — the exact wire form of an idle keep-alive frame.</summary>
        public static readonly byte[] KeepAliveBytes = Encoding.ASCII.GetBytes(KeepAliveText);

        /// <summary>
        /// The block-count sentinel (<c>KEEP_ALIVE_MAGIC = 0xFFFFFFFF</c> — Cedar <c>Cedar.h</c>) a SoftEther peer puts
        /// where a data block's frame count goes to mark the block as a keep-alive. A keep-alive block is therefore
        /// <c>uint32(0xFFFFFFFF) · uint32(size) · size random bytes</c> (not a framed Ethernet payload); the receiver
        /// reads and discards it. Sending keep-alives this way (rather than as a 1-frame block) matches the genuine
        /// client so the server's switch never tries to inject the keep-alive as an Ethernet frame.
        /// </summary>
        public const uint KeepAliveMagic = 0xFFFFFFFFu;

        /// <summary>Upper bound (bytes) on a keep-alive block's random padding (<c>MAX_KEEPALIVE_SIZE</c>); a guard on the inbound size.</summary>
        public const int MaxKeepAliveSize = 512;

        /// <summary>
        /// Upper bound on the number of frames a single data block may declare, guarding against a hostile length prefix
        /// forcing a huge allocation. Generous relative to any real batch (SoftEther sends a handful of frames per block).
        /// </summary>
        public const int MaxFramesPerBlock = 4096;

        /// <summary>
        /// Upper bound (bytes) on a single declared frame size, guarding against a hostile length prefix. Comfortably
        /// above a jumbo Ethernet frame.
        /// </summary>
        public const int MaxFrameSize = 16 * 1024;
    }
}
