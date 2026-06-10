using System;

namespace TqkLibrary.Vpn.IpStack.Tcp
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

        /// <summary>Creates the options; any argument left <c>null</c> takes its RFC 6298 default.</summary>
        public TcpRetransmitOptions(
            TimeSpan? initialRto = null,
            TimeSpan? minRto = null,
            TimeSpan? maxRto = null,
            int maxRetransmits = 5,
            TimeSpan? persistMin = null,
            TimeSpan? persistMax = null,
            TimeSpan? timeWait = null)
        {
            InitialRto = initialRto ?? TimeSpan.FromSeconds(1);
            MinRto = minRto ?? TimeSpan.FromSeconds(1);
            MaxRto = maxRto ?? TimeSpan.FromSeconds(60);
            MaxRetransmits = maxRetransmits;
            PersistMin = persistMin ?? TimeSpan.FromSeconds(1);
            PersistMax = persistMax ?? TimeSpan.FromSeconds(60);
            TimeWait = timeWait ?? TimeSpan.FromSeconds(2);
        }

        /// <summary>RFC 6298 defaults used by the stack when no options are supplied.</summary>
        public static TcpRetransmitOptions Default { get; } = new TcpRetransmitOptions();
    }
}
