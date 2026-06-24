using System;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Enums;

namespace TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions
{
    /// <summary>
    /// Strongly-typed <see cref="ILogger"/> helpers the drivers/protocols call at the cross-cutting trace points
    /// (handshake state, rekey, reconnect, packet drop). Each maps to a stable <see cref="VpnEventIds"/> entry and emits
    /// structured fields (driver name, state, drop reason) so a consumer can filter without parsing free text. They are
    /// thin <see cref="LoggerMessage.Define{T}(LogLevel, EventId, string)"/> wrappers — allocation-free and a no-op when
    /// the level is disabled, so wiring a <see cref="Microsoft.Extensions.Logging.Abstractions.NullLogger"/> (the
    /// default when no <see cref="ILoggerFactory"/> is supplied) costs nothing and never changes behaviour.
    /// </summary>
    public static class VpnLogExtensions
    {
        static readonly Action<ILogger, string, string, Exception?> _stateChanged =
            LoggerMessage.Define<string, string>(LogLevel.Information, VpnEventIds.StateChanged,
                "[{Driver}] state -> {State}");

        static readonly Action<ILogger, string, string, Exception?> _handshake =
            LoggerMessage.Define<string, string>(LogLevel.Debug, VpnEventIds.Handshake,
                "[{Driver}] handshake: {Step}");

        static readonly Action<ILogger, string, Exception?> _handshakeCompleted =
            LoggerMessage.Define<string>(LogLevel.Information, VpnEventIds.HandshakeCompleted,
                "[{Driver}] handshake completed; data plane bound");

        static readonly Action<ILogger, string, string, Exception?> _handshakeFailed =
            LoggerMessage.Define<string, string>(LogLevel.Warning, VpnEventIds.HandshakeFailed,
                "[{Driver}] handshake failed: {Reason}");

        static readonly Action<ILogger, string, string, Exception?> _rekey =
            LoggerMessage.Define<string, string>(LogLevel.Debug, VpnEventIds.Rekey,
                "[{Driver}] rekey: {Phase}");

        static readonly Action<ILogger, string, string, Exception?> _keepalive =
            LoggerMessage.Define<string, string>(LogLevel.Trace, VpnEventIds.Keepalive,
                "[{Driver}] keepalive: {Kind}");

        static readonly Action<ILogger, string, string, Exception?> _linkLost =
            LoggerMessage.Define<string, string>(LogLevel.Warning, VpnEventIds.LinkLost,
                "[{Driver}] link lost: {Reason}");

        static readonly Action<ILogger, string, int, Exception?> _reconnectAttempt =
            LoggerMessage.Define<string, int>(LogLevel.Information, VpnEventIds.ReconnectAttempt,
                "[{Driver}] reconnect attempt #{Attempt}");

        static readonly Action<ILogger, string, Exception?> _reconnected =
            LoggerMessage.Define<string>(LogLevel.Information, VpnEventIds.Reconnected,
                "[{Driver}] reconnected; tunnel re-established");

        static readonly Action<ILogger, string, VpnDropReason, string, Exception?> _packetDropped =
            LoggerMessage.Define<string, VpnDropReason, string>(LogLevel.Debug, VpnEventIds.PacketDropped,
                "[{Driver}] dropped inbound packet ({Reason}): {Detail}");

        static readonly Action<ILogger, string, string, Exception?> _protocolStep =
            LoggerMessage.Define<string, string>(LogLevel.Trace, VpnEventIds.ProtocolStep,
                "[{Layer}] {Step}");

        /// <summary>Logs a lifecycle state transition (Information).</summary>
        public static void LogStateChanged(this ILogger logger, string driver, string state)
            => _stateChanged(logger, driver, state, null);

        /// <summary>Logs a handshake step progressing (Debug).</summary>
        public static void LogHandshake(this ILogger logger, string driver, string step)
            => _handshake(logger, driver, step, null);

        /// <summary>Logs that the handshake completed and the data plane is bound (Information).</summary>
        public static void LogHandshakeCompleted(this ILogger logger, string driver)
            => _handshakeCompleted(logger, driver, null);

        /// <summary>Logs a failed handshake (Warning).</summary>
        public static void LogHandshakeFailed(this ILogger logger, string driver, string reason, Exception? error = null)
            => _handshakeFailed(logger, driver, reason, error);

        /// <summary>Logs a rekey phase (started / channel swapped) (Debug).</summary>
        public static void LogRekey(this ILogger logger, string driver, string phase)
            => _rekey(logger, driver, phase, null);

        /// <summary>Logs a keep-alive / DPD probe sent or answered (Trace).</summary>
        public static void LogKeepalive(this ILogger logger, string driver, string kind)
            => _keepalive(logger, driver, kind, null);

        /// <summary>Logs that the link was lost, with the human-readable reason (Warning).</summary>
        public static void LogLinkLost(this ILogger logger, string driver, string reason)
            => _linkLost(logger, driver, reason, null);

        /// <summary>Logs that a reconnect attempt is starting (Information).</summary>
        public static void LogReconnectAttempt(this ILogger logger, string driver, int attempt)
            => _reconnectAttempt(logger, driver, attempt, null);

        /// <summary>Logs a successful auto-reconnect (Information).</summary>
        public static void LogReconnected(this ILogger logger, string driver)
            => _reconnected(logger, driver, null);

        /// <summary>Logs a dropped inbound packet with a classified reason and a short detail (Debug).</summary>
        public static void LogPacketDropped(this ILogger logger, string driver, VpnDropReason reason, string detail = "")
            => _packetDropped(logger, driver, reason, detail, null);

        /// <summary>
        /// Logs a fine-grained step inside a protocol layer (an IKE Main/Quick Mode message, an ESP SA install/swap, a
        /// PPP LCP/IPCP transition, a TCP state change) at <see cref="LogLevel.Trace"/>. <paramref name="layer"/> names
        /// the protocol layer (e.g. <c>ike</c>, <c>esp</c>, <c>ppp.lcp</c>, <c>tcp</c>). Per-step/per-packet, so callers
        /// on a hot path should guard it with <c>logger.IsEnabled(LogLevel.Trace)</c> before composing the message.
        /// </summary>
        public static void LogProtocolStep(this ILogger logger, string layer, string step)
            => _protocolStep(logger, layer, step, null);
    }
}
