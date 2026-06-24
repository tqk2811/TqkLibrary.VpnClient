using System.Text.Json.Serialization;

namespace TqkLibrary.VpnClient.Tailscale.Control.Messages
{
    /// <summary>
    /// The authentication block of a <see cref="RegisterRequest"/> (<c>tailcfg.RegisterResponseAuth</c>; the Go type is
    /// named "Response" but is used in the request). For preauth-key login only <see cref="AuthKey"/> is set — the
    /// Headscale-issued key from <c>headscale preauthkeys create</c>. JSON key is <c>AuthKey</c> (PascalCase).
    /// </summary>
    public sealed class RegisterResponseAuth
    {
        /// <summary>The preauthentication key (Headscale <c>preauthkeys create</c>). JSON key <c>AuthKey</c>.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? AuthKey { get; set; }
    }
}
