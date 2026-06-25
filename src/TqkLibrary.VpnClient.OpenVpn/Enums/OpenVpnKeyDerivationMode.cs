namespace TqkLibrary.VpnClient.OpenVpn.Enums
{
    /// <summary>
    /// How the OpenVPN data-channel keys are derived from the control-channel TLS session (the <c>--key-derivation</c>
    /// directive, OpenVPN 2.6). The client advertises its support via the <c>IV_PROTO</c> tls-key-export bit and the
    /// server selects the mode in PUSH_REPLY (<c>key-derivation tls-ekm</c>).
    /// </summary>
    public enum OpenVpnKeyDerivationMode
    {
        /// <summary>
        /// Legacy key-method-2 PRF: the two peers exchange <c>key_source2</c> randoms over TLS and blend them with the
        /// TLS 1.0 PRF (<see cref="DataChannel.OpenVpnKeyMethod2.DeriveKey2"/>). The default — the only mode the BCL
        /// <see cref="System.Net.Security.SslStream"/> control channel can drive.
        /// </summary>
        Tls1Prf = 0,

        /// <summary>
        /// <c>tls-ekm</c> (RFC 5705): the data-channel key material is exported directly from the finished control-channel
        /// TLS session over the label <c>"EXPORTER-OpenVPN-datakeys"</c> (256 bytes, empty context), replacing the
        /// key-method-2 PRF blend. Requires a BouncyCastle TLS control channel (the BCL SslStream exposes no RFC 5705
        /// exporter on netstandard2.0/net8.0).
        /// </summary>
        TlsEkm = 1,
    }
}
