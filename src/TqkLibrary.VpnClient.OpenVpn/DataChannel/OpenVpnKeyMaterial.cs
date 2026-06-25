namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// The cipher-independent result of key-method-2: the raw 256-byte key2. The data cipher may be negotiated only
    /// after key exchange (NCP — the server echoes it in PUSH_REPLY, V2.f), so the negotiation hands back this material
    /// and the caller slices it once the cipher is known via <see cref="DeriveDataKeys"/>. The same wrapper also carries
    /// the 256-byte key material exported via <c>tls-ekm</c> (RFC 5705, see <see cref="FromTlsExporter"/>), which slices
    /// identically.
    /// </summary>
    public sealed class OpenVpnKeyMaterial
    {
        readonly byte[] _key2;

        /// <summary>Wraps the derived 256-byte key2.</summary>
        public OpenVpnKeyMaterial(byte[] key2)
        {
            if (key2 is null) throw new ArgumentNullException(nameof(key2));
            if (key2.Length != OpenVpnStaticKey.KeyLength)
                throw new ArgumentException($"key2 must be {OpenVpnStaticKey.KeyLength} bytes.", nameof(key2));
            _key2 = key2;
        }

        /// <summary>The RFC 5705 exporter label OpenVPN's <c>key-derivation tls-ekm</c> uses.</summary>
        public const string TlsEkmLabel = "EXPORTER-OpenVPN-datakeys";

        /// <summary>
        /// Derives the 256-byte key material from the control-channel TLS session via the RFC 5705 keying-material exporter
        /// (<c>key-derivation tls-ekm</c>): <c>TLS-Exporter("EXPORTER-OpenVPN-datakeys", empty context, 256)</c>, replacing
        /// the legacy key-method-2 PRF blend. The 256 bytes carry the same <c>{cipher[64]|hmac[64]} × 2</c> structure
        /// (<c>key_c2s | auth_c2s | key_s2c | auth_s2c</c>), so <see cref="DeriveDataKeys"/> / <see cref="DeriveCbcDataKeys"/>
        /// slice it for the negotiated cipher exactly as for the PRF-derived key2 (client out = c2s, in = s2c).
        /// </summary>
        public static OpenVpnKeyMaterial FromTlsExporter(TqkLibrary.VpnClient.OpenVpn.ITlsKeyingMaterialExporter exporter)
        {
            if (exporter is null) throw new ArgumentNullException(nameof(exporter));
            byte[] key2 = exporter.Export(TlsEkmLabel, ReadOnlySpan<byte>.Empty, OpenVpnStaticKey.KeyLength);
            return new OpenVpnKeyMaterial(key2);
        }

        /// <summary>Slices the data-channel keys for the negotiated <paramref name="cipher"/> (client role by default).</summary>
        public OpenVpnDataChannelKeys DeriveDataKeys(OpenVpnDataCipher cipher, bool isServer = false)
            => OpenVpnKeyMethod2.SliceDataKeys(_key2, cipher, isServer);

        /// <summary>
        /// Slices the non-AEAD CBC data-channel keys for <paramref name="cipher"/> (AES-CBC) + a
        /// <paramref name="hmacKeyLen"/>-byte HMAC key (from <c>--auth</c>). Client role by default.
        /// </summary>
        public OpenVpnCbcDataKeys DeriveCbcDataKeys(OpenVpnCbcCipher cipher, int hmacKeyLen, bool isServer = false)
        {
            if (cipher is null) throw new ArgumentNullException(nameof(cipher));
            return OpenVpnKeyMethod2.SliceCbcDataKeys(_key2, cipher.KeySizeBytes, hmacKeyLen, isServer);
        }
    }
}
