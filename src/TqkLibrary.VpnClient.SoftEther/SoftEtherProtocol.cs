namespace TqkLibrary.VpnClient.SoftEther
{
    /// <summary>
    /// Constants for the SoftEther SSL-VPN control exchange: HTTP request targets, the PACK element names used by the
    /// hello/login/welcome messages, and the fixed sizes the protocol mandates. Re-implemented from the protocol
    /// behavior (spec doc <c>07</c>) — not copied from the GPL source. Centralised here so the watermark/handshake/auth
    /// codecs share one authoritative set of field names.
    /// </summary>
    public static class SoftEtherProtocol
    {
        // ---- HTTP targets ----------------------------------------------------------------------------

        /// <summary>The HTTP request target of the watermark POST that opens a SoftEther session.</summary>
        public const string ConnectTarget = "/vpnsvc/connect.cgi";

        /// <summary>The HTTP request target for every PACK exchanged after the watermark (hello/login/welcome).</summary>
        public const string VpnTarget = "/vpnsvc/vpn.cgi";

        // ---- Hello (server → client) -----------------------------------------------------------------

        /// <summary>STR element naming the server greeting (value <c>"softether"</c>).</summary>
        public const string HelloName = "hello";

        /// <summary>INT element carrying the server protocol version in the hello PACK.</summary>
        public const string VersionName = "version";

        /// <summary>INT element carrying the server build number in the hello PACK.</summary>
        public const string BuildName = "build";

        /// <summary>DATA element carrying the 20-byte server random challenge in the hello PACK.</summary>
        public const string RandomName = "random";

        // ---- Login (client → server) -----------------------------------------------------------------

        /// <summary>STR element naming the request method (value <c>"login"</c> for an authentication request).</summary>
        public const string MethodName = "method";

        /// <summary>The <see cref="MethodName"/> value for an authentication request.</summary>
        public const string MethodLogin = "login";

        /// <summary>
        /// The <see cref="MethodName"/> value for an <b>additional connection</b> request: a secondary TCP/TLS
        /// connection that reattaches to an already-established logical session (the server looks it up by the session
        /// key from the <c>welcome</c> PACK via its <c>GetSessionFromKey</c>), pooling throughput across 1–32 sockets.
        /// </summary>
        public const string MethodAdditionalConnect = "additional_connect";

        /// <summary>STR element carrying the target Virtual Hub name.</summary>
        public const string HubNameName = "hubname";

        /// <summary>STR element carrying the user name.</summary>
        public const string UserNameName = "username";

        /// <summary>INT element carrying the <see cref="Enums.SoftEtherAuthType"/>.</summary>
        public const string AuthTypeName = "authtype";

        /// <summary>DATA element carrying the SHA-0 secure password (20 bytes) for password auth.</summary>
        public const string SecurePasswordName = "secure_password";

        /// <summary>STR element carrying the plaintext password for plain-password (RADIUS/NT) auth.</summary>
        public const string PlainPasswordName = "plain_password";

        /// <summary>INT element carrying the requested number of parallel TCP connections.</summary>
        public const string MaxConnectionName = "max_connection";

        /// <summary>INT (bool) element requesting RC4 payload encryption.</summary>
        public const string UseEncryptName = "use_encrypt";

        /// <summary>INT (bool) element requesting deflate payload compression.</summary>
        public const string UseCompressName = "use_compress";

        /// <summary>INT (bool) element requesting half-duplex connections.</summary>
        public const string HalfConnectionName = "half_connection";

        /// <summary>DATA element carrying the per-client unique id.</summary>
        public const string UniqueIdName = "unique_id";

        /// <summary>STR element naming the client product (informational).</summary>
        public const string ClientStrName = "client_str";

        /// <summary>INT element carrying the client product version (informational).</summary>
        public const string ClientVerName = "client_ver";

        /// <summary>INT element carrying the client build number (informational).</summary>
        public const string ClientBuildName = "client_build";

        // ---- Welcome / error (server → client) -------------------------------------------------------

        /// <summary>
        /// DATA element carrying the 20-byte session-key handle in the welcome PACK — the value an additional
        /// connection echoes back (<c>additional_connect</c>) so the server's <c>GetSessionFromKey</c> reattaches it.
        /// (The genuine server adds it as <c>PackAddData(p, "session_key", …, SHA1_SIZE)</c> — Cedar <c>Protocol.c</c>;
        /// the separate STR <c>session_name</c> is the human-readable session name, not the key.)
        /// </summary>
        public const string SessionKeyName = "session_key";

        /// <summary>STR element carrying the human-readable session name in the welcome PACK (informational, not the key).</summary>
        public const string SessionNameName = "session_name";

        /// <summary>INT element carrying the 32-bit fast session key in the welcome PACK (<c>session_key_32</c>).</summary>
        public const string SessionKey32Name = "session_key_32";

        /// <summary>
        /// INT element echoing the number of parallel TCP connections the server granted for the session (welcome PACK).
        /// Reuses the same name as the login request field (<see cref="MaxConnectionName"/>).
        /// </summary>
        public const string MaxConnectionWelcomeName = MaxConnectionName;

        /// <summary>INT element carrying a SoftEther error code (non-zero ⇒ the request failed).</summary>
        public const string ErrorName = "error";

        // ---- Fixed sizes -----------------------------------------------------------------------------

        /// <summary>Length (bytes) of the server random challenge and of a SHA-0 hash.</summary>
        public const int RandomSize = 20;

        /// <summary>The <c>hello</c> greeting string a SoftEther server sends.</summary>
        public const string HelloValue = "softether";
    }
}
