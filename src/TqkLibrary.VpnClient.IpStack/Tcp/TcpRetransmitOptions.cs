using System;

namespace TqkLibrary.VpnClient.IpStack.Tcp
{
    /// <summary>
    /// Tunables for the userspace TCP send path: the retransmission timer (RFC 6298) and the zero-window
    /// persist timer. Defaults follow RFC 6298 (1s initial/min RTO, ×2 backoff capped at 60s, give up after
    /// 5 retries). The stack uses <see cref="Default"/>; tests build a <see cref="TcpConnection"/> with much
    /// shorter timers so retransmission/persist/give-up paths run deterministically and fast.
    /// </summary>
    /// <remarks>
    /// Plain class (no <c>record</c>/<c>init</c>) so it compiles on <c>netstandard2.0</c>; all values are
    /// constructor-set and read-only, so <see cref="Default"/> is safe to share.
    /// </remarks>
    public sealed class TcpRetransmitOptions
    {
        /// <summary>RTO used before any RTT sample exists (RFC 6298 §2.1 recommends 1 second).</summary>
        public TimeSpan InitialRto { get; }

        /// <summary>Lower bound for the computed RTO (RFC 6298 §2.4 recommends rounding up to 1 second).</summary>
        public TimeSpan MinRto { get; }

        /// <summary>Upper bound for the backed-off RTO (RFC 6298 §2.5 allows a cap ≥ 60 seconds).</summary>
        public TimeSpan MaxRto { get; }

        /// <summary>Fault the connection after this many consecutive RTO retransmits of the oldest unacked segment without forward progress.</summary>
        public int MaxRetransmits { get; }

        /// <summary>First zero-window persist interval (probe a peer that advertised a zero receive window).</summary>
        public TimeSpan PersistMin { get; }

        /// <summary>Maximum zero-window persist interval after exponential backoff.</summary>
        public TimeSpan PersistMax { get; }

        /// <summary>How long to linger in TIME-WAIT before closing (RFC 793 uses 2×MSL; a userspace socket can be far shorter).</summary>
        public TimeSpan TimeWait { get; }

        /// <summary>
        /// How long to wait in FIN-WAIT-2 for the peer's FIN before resetting the connection.
        /// </summary>
        /// <remarks>
        /// RFC 9293 gives this wait no bound, which is fine for a kernel that can afford idle
        /// sockets and wrong for a tunnel: a peer that is simply not finished talking never sends
        /// a FIN, and the half-closed connection keeps its port and its receive queue for the life
        /// of the tunnel. Linux bounds it the same way (tcp_fin_timeout, 60 s by default).
        /// </remarks>
        public TimeSpan FinWait2 { get; }

        /// <summary>
        /// High-water mark (bytes) for unsent application data buffered by <see cref="TcpConnection.SendAsync"/>: once the
        /// buffer reaches this, a writer awaits until the peer's window drains it (backpressure) instead of buffering without
        /// bound. Tests set a tiny value so the blocking path is reached with small writes.
        /// </summary>
        public int SendBufferHighWaterMark { get; }

        /// <summary>Creates the options; any argument left <c>null</c> takes its RFC 6298 default.</summary>
        public TcpRetransmitOptions(
            TimeSpan? initialRto = null,
            TimeSpan? minRto = null,
            TimeSpan? maxRto = null,
            int maxRetransmits = 5,
            TimeSpan? persistMin = null,
            TimeSpan? persistMax = null,
            TimeSpan? timeWait = null,
            int sendBufferHighWaterMark = 64 * 1024,
            TimeSpan? finWait2 = null)
        {
            InitialRto = initialRto ?? TimeSpan.FromSeconds(1);
            MinRto = minRto ?? TimeSpan.FromSeconds(1);
            MaxRto = maxRto ?? TimeSpan.FromSeconds(60);
            MaxRetransmits = maxRetransmits;
            PersistMin = persistMin ?? TimeSpan.FromSeconds(1);
            PersistMax = persistMax ?? TimeSpan.FromSeconds(60);
            TimeWait = timeWait ?? TimeSpan.FromSeconds(2);
            FinWait2 = finWait2 ?? TimeSpan.FromSeconds(60);
            SendBufferHighWaterMark = sendBufferHighWaterMark > 0 ? sendBufferHighWaterMark : 64 * 1024;
        }

        /// <summary>RFC 6298 defaults used by the stack when no options are supplied.</summary>
        public static TcpRetransmitOptions Default { get; } = new TcpRetransmitOptions();
    }
}
