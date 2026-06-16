namespace TqkLibrary.VpnClient.SoftEther.Enums
{
    /// <summary>
    /// SoftEther client authentication method, serialized as the <c>authtype</c> INT field of the <c>login</c> PACK.
    /// Numeric values are fixed by the protocol (re-implemented from the spec — not copied from the GPL source).
    /// V4.b implements <see cref="Password"/> (SHA-0 password hashing); the other modes are catalogued for later.
    /// </summary>
    public enum SoftEtherAuthType : uint
    {
        /// <summary>Anonymous authentication (<c>CLIENT_AUTHTYPE_ANONYMOUS</c>): no credential.</summary>
        Anonymous = 0,

        /// <summary>
        /// Password authentication (<c>CLIENT_AUTHTYPE_PASSWORD</c>): the <c>secure_password</c> field carries
        /// <c>SHA0(SHA0(password‖UPPER(username))‖server_random)</c> — the plaintext password never crosses the wire.
        /// </summary>
        Password = 1,

        /// <summary>Plain-password authentication forwarded to an external RADIUS/NT server (<c>CLIENT_AUTHTYPE_PLAIN_PASSWORD</c>).</summary>
        PlainPassword = 2,

        /// <summary>X.509 client-certificate authentication (<c>CLIENT_AUTHTYPE_CERT</c>).</summary>
        Certificate = 3,
    }
}
