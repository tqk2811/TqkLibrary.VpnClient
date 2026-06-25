using TqkLibrary.VpnClient.OpenVpn.Enums;

namespace TqkLibrary.VpnClient.OpenVpn.Config
{
    /// <summary>
    /// The programmatic OpenVPN configuration the driver consumes. It is what every V.2 phase reads (remote(s),
    /// transport, device, TLS material, cipher/auth, options); <see cref="OpenVpnConfigParser"/> produces one from a
    /// .ovpn file, but it can equally be built by hand. Fields mirror the common .ovpn directives; anything the parser
    /// does not model is preserved verbatim in <see cref="OtherDirectives"/> so nothing is silently lost.
    /// </summary>
    public sealed class OpenVpnProfile
    {
        // ---- endpoint / transport ----

        /// <summary>The server endpoints from <c>remote</c> directives (first is preferred; the rest are fallbacks).</summary>
        public List<OpenVpnRemote> Remotes { get; } = new();

        /// <summary>Profile-wide transport (<c>proto</c>); a remote may override it. Default UDP.</summary>
        public OpenVpnProtocol Protocol { get; set; } = OpenVpnProtocol.Udp;

        /// <summary>Default port (<c>port</c>) applied to remotes that did not state their own. Default 1194.</summary>
        public int Port { get; set; } = 1194;

        /// <summary>Virtual device type (<c>dev</c>/<c>dev-type</c>). Default tun.</summary>
        public OpenVpnDeviceType Device { get; set; } = OpenVpnDeviceType.Tun;

        /// <summary>True when the profile contains the <c>client</c> directive (or <c>tls-client</c>).</summary>
        public bool IsClient { get; set; }

        // ---- TLS material ----

        /// <summary>CA certificate (<c>ca</c>): inline PEM or a file path.</summary>
        public OpenVpnFileOrInline? Ca { get; set; }

        /// <summary>Client certificate (<c>cert</c>): inline PEM or a file path.</summary>
        public OpenVpnFileOrInline? Cert { get; set; }

        /// <summary>Client private key (<c>key</c>): inline PEM or a file path.</summary>
        public OpenVpnFileOrInline? Key { get; set; }

        /// <summary>tls-auth static key (<c>tls-auth</c>): HMAC-wraps control packets (V2.c).</summary>
        public OpenVpnFileOrInline? TlsAuth { get; set; }

        /// <summary>tls-crypt static key (<c>tls-crypt</c>): encrypts + authenticates control packets (V2.c).</summary>
        public OpenVpnFileOrInline? TlsCrypt { get; set; }

        /// <summary>tls-crypt-v2 client key (<c>tls-crypt-v2</c>).</summary>
        public OpenVpnFileOrInline? TlsCryptV2 { get; set; }

        /// <summary>Static-key direction for tls-auth (<c>key-direction</c> or the tls-auth third arg); null = bidirectional.</summary>
        public int? KeyDirection { get; set; }

        // ---- credentials ----

        /// <summary>True when <c>auth-user-pass</c> is present (the session prompts for / supplies a username+password).</summary>
        public bool AuthUserPass { get; set; }

        /// <summary>The file referenced by <c>auth-user-pass &lt;file&gt;</c>, if any (the caller resolves it).</summary>
        public string? AuthUserPassFile { get; set; }

        // ---- crypto suite ----

        /// <summary>Legacy single data cipher (<c>cipher</c>), e.g. <c>AES-256-GCM</c>.</summary>
        public string? Cipher { get; set; }

        /// <summary>NCP cipher list (<c>data-ciphers</c>, colon-separated) negotiated with the server (V2.f).</summary>
        public List<string> DataCiphers { get; } = new();

        /// <summary>HMAC for CBC data mode / control auth (<c>auth</c>), e.g. <c>SHA256</c>.</summary>
        public string? Auth { get; set; }

        /// <summary>
        /// Data-channel key derivation (<c>key-derivation</c>, OpenVPN 2.6). Default <see cref="OpenVpnKeyDerivationMode.Tls1Prf"/>
        /// (key-method-2 PRF over <see cref="System.Net.Security.SslStream"/>); <see cref="OpenVpnKeyDerivationMode.TlsEkm"/>
        /// routes the control channel through BouncyCastle and exports the keys via RFC 5705 (<c>tls-ekm</c>).
        /// </summary>
        public OpenVpnKeyDerivationMode KeyDerivation { get; set; } = OpenVpnKeyDerivationMode.Tls1Prf;

        // ---- misc options ----

        /// <summary>True when <c>remote-cert-tls server</c> is set (verify the peer cert is a server cert).</summary>
        public bool RemoteCertTlsServer { get; set; }

        /// <summary>Compression directive value (<c>comp-lzo</c>/<c>compress</c>), e.g. <c>no</c>/<c>stub</c>; null = none.</summary>
        public string? Compression { get; set; }

        /// <summary>TLS renegotiation interval in seconds (<c>reneg-sec</c>), if set.</summary>
        public int? RenegSec { get; set; }

        /// <summary>tun MTU (<c>tun-mtu</c>), if set.</summary>
        public int? TunMtu { get; set; }

        /// <summary>Directives the parser did not model, kept verbatim (name → list of argument-lists, in file order).</summary>
        public Dictionary<string, List<string[]>> OtherDirectives { get; } = new();
    }
}
