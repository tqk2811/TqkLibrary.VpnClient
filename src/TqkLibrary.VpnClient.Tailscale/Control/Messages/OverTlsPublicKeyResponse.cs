using System.Text.Json.Serialization;

namespace TqkLibrary.VpnClient.Tailscale.Control.Messages
{
    /// <summary>
    /// The JSON body of the <c>GET /key?v=&lt;capver&gt;</c> endpoint (<c>tailcfg.OverTLSPublicKeyResponse</c>). It
    /// carries the control server's machine public key (the Noise IK responder static). Headscale sets only
    /// <see cref="PublicKey"/> (the Noise-era key) and leaves <see cref="LegacyPublicKey"/> empty, so the client must use
    /// <see cref="PublicKey"/>. Both are <c>mkey:&lt;hex&gt;</c> text.
    /// </summary>
    public sealed class OverTlsPublicKeyResponse
    {
        /// <summary>The legacy (pre-Noise) machine public key; empty on Headscale. JSON key <c>legacyPublicKey</c>.</summary>
        [JsonPropertyName("legacyPublicKey")]
        public string? LegacyPublicKey { get; set; }

        /// <summary>The current machine public key (<c>mkey:&lt;hex&gt;</c>) — the ts2021 Noise responder static. JSON key <c>publicKey</c>.</summary>
        [JsonPropertyName("publicKey")]
        public string? PublicKey { get; set; }
    }
}
