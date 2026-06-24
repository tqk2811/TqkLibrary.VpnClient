namespace TqkLibrary.VpnClient.Tailscale.Control.Messages
{
    /// <summary>
    /// The response to <c>POST /machine/register</c> (<c>tailcfg.RegisterResponse</c>). When <see cref="Error"/> is
    /// non-empty the other fields are ignored. <see cref="MachineAuthorized"/> indicates the node is approved (a valid
    /// preauth key authorizes immediately); a non-empty <see cref="AuthURL"/> means interactive login is required
    /// (the preauth path should not produce one). JSON keys are PascalCase (Go field names verbatim).
    /// </summary>
    public sealed class RegisterResponse
    {
        /// <summary>Whether the node is authorized to proceed to the map step.</summary>
        public bool MachineAuthorized { get; set; }

        /// <summary>Whether the supplied node key has expired.</summary>
        public bool NodeKeyExpired { get; set; }

        /// <summary>An interactive-login URL when set; empty for a successful preauth registration.</summary>
        public string? AuthURL { get; set; }

        /// <summary>A non-empty error string overrides every other field (e.g. an invalid preauth key).</summary>
        public string? Error { get; set; }
    }
}
