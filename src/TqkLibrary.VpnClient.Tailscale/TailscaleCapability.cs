namespace TqkLibrary.VpnClient.Tailscale
{
    /// <summary>
    /// Tailscale ts2021 protocol constants. The capability version is a monotonically increasing integer the client
    /// advertises in <c>RegisterRequest.Version</c> / <c>MapRequest.Version</c> and in <c>/key?v=</c>. Headscale rejects
    /// values below its <c>MinSupportedCapabilityVersion</c> (113 at time of writing) with HTTP 400, so the default sits
    /// in the supported band. The ts2021 control-protocol (frame) version is a separate, small value (1).
    /// </summary>
    public static class TailscaleCapability
    {
        /// <summary>
        /// The capability version advertised to the control server. Chosen in the Headscale-supported band
        /// (≥ <c>MinSupportedCapabilityVersion</c>); a moderately recent value avoids both "too old" (400) rejections
        /// and depending on features of the very latest clients.
        /// </summary>
        public const int CapabilityVersion = 113;

        /// <summary>The ts2021 control-protocol (Noise frame) version negotiated in the initiation header / prologue.</summary>
        public const int ControlProtocolVersion = 1;
    }
}
