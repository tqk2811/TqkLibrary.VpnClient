namespace TqkLibrary.VpnClient.Pptp.Enums
{
    /// <summary>
    /// Simplified state of the PPTP control-connection / call state machine driven by
    /// <see cref="PptpControlConnection"/> (RFC 2637 §3.1.1 control-connection FSM + §3.1.2 call FSM, reduced to
    /// the PNS/client path this library needs).
    /// </summary>
    public enum PptpControlState
    {
        /// <summary>Nothing started.</summary>
        Idle = 0,

        /// <summary>Start-Control-Connection-Request sent, awaiting the reply.</summary>
        ControlConnectionRequested,

        /// <summary>Control connection is established (Start-Control-Connection-Reply OK).</summary>
        ControlConnectionEstablished,

        /// <summary>Outgoing-Call-Request sent, awaiting the reply.</summary>
        OutgoingCallRequested,

        /// <summary>Call is up (Outgoing-Call-Reply OK) — the GRE data plane would run here.</summary>
        CallEstablished,

        /// <summary>A teardown (Call-Clear/Stop) has been issued or received.</summary>
        Closing,

        /// <summary>The control connection is closed.</summary>
        Closed,
    }
}
