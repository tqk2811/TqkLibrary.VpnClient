using Microsoft.Extensions.Logging;

namespace TqkLibrary.VpnClient.Abstractions.Diagnostics
{
    /// <summary>
    /// The stable <see cref="EventId"/> set the drivers/protocols stamp on their diagnostic log entries so a consumer
    /// can filter by event kind (handshake progress vs. a dropped packet vs. a reconnect) regardless of which driver
    /// emitted it. The numeric ids are grouped by lifecycle stage (1xx connect/handshake, 2xx steady-state, 3xx
    /// reconnect, 4xx drops) and are part of the contract — add new ids, do not renumber existing ones.
    /// </summary>
    public static class VpnEventIds
    {
        // ---- 1xx: connect / handshake ----

        /// <summary>The connection moved to a new lifecycle state (Connecting/Connected/Reconnecting/Disconnected).</summary>
        public static readonly EventId StateChanged = new(100, nameof(StateChanged));

        /// <summary>A handshake step progressed (initiation sent, response consumed, login accepted, tunnel config received).</summary>
        public static readonly EventId Handshake = new(101, nameof(Handshake));

        /// <summary>The handshake completed and the data plane is now bound (the tunnel is carrying traffic).</summary>
        public static readonly EventId HandshakeCompleted = new(102, nameof(HandshakeCompleted));

        /// <summary>The handshake failed (auth rejected, AEAD/MAC mismatch, timed out with no response).</summary>
        public static readonly EventId HandshakeFailed = new(103, nameof(HandshakeFailed));

        // ---- 2xx: steady state ----

        /// <summary>A rekey was started or completed (a fresh handshake/keys replacing the live session, make-before-break).</summary>
        public static readonly EventId Rekey = new(200, nameof(Rekey));

        /// <summary>A keep-alive / dead-peer-detection probe was sent or answered.</summary>
        public static readonly EventId Keepalive = new(201, nameof(Keepalive));

        // ---- 3xx: link loss / reconnect ----

        /// <summary>The link was lost (peer closed, DPD fired, transport faulted) — the reason is the message.</summary>
        public static readonly EventId LinkLost = new(300, nameof(LinkLost));

        /// <summary>A reconnect attempt is starting (after a backoff delay).</summary>
        public static readonly EventId ReconnectAttempt = new(301, nameof(ReconnectAttempt));

        /// <summary>The tunnel was re-established by the auto-reconnect supervisor.</summary>
        public static readonly EventId Reconnected = new(302, nameof(Reconnected));

        // ---- 4xx: dropped packets ----

        /// <summary>An inbound packet/frame was dropped (decrypt/AEAD failure, MAC/auth mismatch, replay, malformed, unexpected type).</summary>
        public static readonly EventId PacketDropped = new(400, nameof(PacketDropped));

        // ---- 5xx: deep protocol trace (IKE/ESP/PPP/IpStack per-step / per-packet) ----

        /// <summary>A fine-grained step inside a protocol layer (an individual IKE Main/Quick Mode message, an ESP SA
        /// install/swap, a PPP LCP/IPCP option-negotiation transition, a TCP state change). Trace level — emitted per
        /// step/packet, so it is off unless a consumer raises a protocol category to <see cref="LogLevel.Trace"/>.</summary>
        public static readonly EventId ProtocolStep = new(500, nameof(ProtocolStep));
    }
}
