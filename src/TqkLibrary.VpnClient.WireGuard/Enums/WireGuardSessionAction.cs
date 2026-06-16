namespace TqkLibrary.VpnClient.WireGuard.Enums
{
    /// <summary>
    /// The single action a <see cref="WireGuardPeerState"/> tells the driver to take right now, derived purely from
    /// the clock and the message counters (WireGuard whitepaper §6.2). The driver evaluates it on every timer tick and
    /// after every packet; the values are ordered by urgency so the most pressing one wins.
    /// </summary>
    public enum WireGuardSessionAction
    {
        /// <summary>Nothing to do — the current session is fresh and within all limits.</summary>
        None = 0,

        /// <summary>A passive or persistent keepalive is due (send an empty type-4 transport packet).</summary>
        SendKeepalive,

        /// <summary>Start a new handshake — there is no live session yet, or the current one crossed the re-key watermark
        /// (<c>REKEY_AFTER_TIME</c> / <c>REKEY_AFTER_MESSAGES</c>) and should be replaced make-before-break.</summary>
        InitiateHandshake,

        /// <summary>Resend the pending handshake initiation — it has been unanswered for <c>REKEY_TIMEOUT</c> (+jitter).</summary>
        ResendHandshake,

        /// <summary>Give up the in-flight handshake and tear the session down — it has been retrying for
        /// <c>REKEY_ATTEMPT_TIME</c> with no response.</summary>
        AbandonHandshake,

        /// <summary>The current session is unusable — it passed <c>REJECT_AFTER_TIME</c> / <c>REJECT_AFTER_MESSAGES</c>;
        /// stop sending on it and (if not already) start a handshake or tear down.</summary>
        SessionDead,
    }
}
