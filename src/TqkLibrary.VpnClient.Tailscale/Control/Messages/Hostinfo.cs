using System.Text.Json.Serialization;

namespace TqkLibrary.VpnClient.Tailscale.Control.Messages
{
    /// <summary>
    /// Host metadata sent in <see cref="RegisterRequest"/> and <see cref="MapRequest"/> (<c>tailcfg.Hostinfo</c>). Only
    /// the few fields a minimal client needs are modelled; the rest are omitted (Go omitempty). JSON keys are
    /// PascalCase. <see cref="RoutableIPs"/> advertises subnet routes this node offers (CIDR strings).
    /// </summary>
    public sealed class Hostinfo
    {
        /// <summary>The reported hostname.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Hostname { get; set; }

        /// <summary>The operating system string (e.g. <c>linux</c>, <c>windows</c>).</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? OS { get; set; }

        /// <summary>The client version string this node reports.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? IPNVersion { get; set; }

        /// <summary>Subnet routes this node advertises (CIDR strings); omitted when empty.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public IReadOnlyList<string>? RoutableIPs { get; set; }
    }
}
