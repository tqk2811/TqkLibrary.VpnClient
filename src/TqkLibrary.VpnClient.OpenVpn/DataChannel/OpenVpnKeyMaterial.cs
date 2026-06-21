namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// The cipher-independent result of key-method-2: the raw 256-byte key2. The data cipher may be negotiated only
    /// after key exchange (NCP — the server echoes it in PUSH_REPLY, V2.f), so the negotiation hands back this material
    /// and the caller slices it once the cipher is known via <see cref="DeriveDataKeys"/>.
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
