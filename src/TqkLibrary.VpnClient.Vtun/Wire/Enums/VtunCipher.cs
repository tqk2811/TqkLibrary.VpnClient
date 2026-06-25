namespace TqkLibrary.VpnClient.Vtun.Wire.Enums
{
    /// <summary>
    /// The vtun data-plane cipher identifiers (<c>vtun.h</c>'s <c>VTUN_ENC_*</c> macros) carried as the <c>E&lt;n&gt;</c>
    /// argument in the host-flags string. The server picks one; the client must use the matching cipher on the data plane.
    /// The numeric values match the C macros so a parsed id maps straight through.
    /// <para>
    /// vtun's <c>encrypt yes</c> (no explicit method) and the legacy bare <c>E</c> token both resolve to
    /// <see cref="Blowfish128Ecb"/> (vtund's <c>alloc_encrypt</c> <c>default:</c> branch). That is the one mode this
    /// driver implements today; the remaining ids are listed so an unsupported selection is named precisely in the error.
    /// </para>
    /// ⚠️ vtun's data-plane ciphers are legacy: the default (Blowfish-128-ECB) has no chaining, no IV and no
    /// authentication — it leaks plaintext structure and is trivially malleable. It exists here only to interoperate with
    /// the vtund daemon, never as a recommended cipher.
    /// </summary>
    public enum VtunCipher
    {
        /// <summary>No data-plane encryption (the <c>encrypt no</c> default).</summary>
        None = 0,

        /// <summary>Blowfish, 128-bit key, ECB (<c>VTUN_ENC_BF128ECB</c>) — vtun's <c>encrypt yes</c> default.</summary>
        Blowfish128Ecb = 1,

        /// <summary>Blowfish, 128-bit key, CBC (<c>VTUN_ENC_BF128CBC</c>).</summary>
        Blowfish128Cbc = 2,

        /// <summary>Blowfish, 128-bit key, CFB (<c>VTUN_ENC_BF128CFB</c>).</summary>
        Blowfish128Cfb = 3,

        /// <summary>Blowfish, 128-bit key, OFB (<c>VTUN_ENC_BF128OFB</c>).</summary>
        Blowfish128Ofb = 4,

        /// <summary>Blowfish, 256-bit key, ECB (<c>VTUN_ENC_BF256ECB</c>).</summary>
        Blowfish256Ecb = 5,

        /// <summary>Blowfish, 256-bit key, CBC (<c>VTUN_ENC_BF256CBC</c>).</summary>
        Blowfish256Cbc = 6,

        /// <summary>Blowfish, 256-bit key, CFB (<c>VTUN_ENC_BF256CFB</c>).</summary>
        Blowfish256Cfb = 7,

        /// <summary>Blowfish, 256-bit key, OFB (<c>VTUN_ENC_BF256OFB</c>).</summary>
        Blowfish256Ofb = 8,

        /// <summary>AES, 128-bit key, ECB (<c>VTUN_ENC_AES128ECB</c>).</summary>
        Aes128Ecb = 9,

        /// <summary>AES, 128-bit key, CBC (<c>VTUN_ENC_AES128CBC</c>).</summary>
        Aes128Cbc = 10,

        /// <summary>AES, 128-bit key, CFB (<c>VTUN_ENC_AES128CFB</c>).</summary>
        Aes128Cfb = 11,

        /// <summary>AES, 128-bit key, OFB (<c>VTUN_ENC_AES128OFB</c>).</summary>
        Aes128Ofb = 12,

        /// <summary>AES, 256-bit key, ECB (<c>VTUN_ENC_AES256ECB</c>).</summary>
        Aes256Ecb = 13,

        /// <summary>AES, 256-bit key, CBC (<c>VTUN_ENC_AES256CBC</c>).</summary>
        Aes256Cbc = 14,

        /// <summary>AES, 256-bit key, CFB (<c>VTUN_ENC_AES256CFB</c>).</summary>
        Aes256Cfb = 15,

        /// <summary>AES, 256-bit key, OFB (<c>VTUN_ENC_AES256OFB</c>).</summary>
        Aes256Ofb = 16,

        /// <summary>Legacy bare <c>E</c> token (vtun's <c>VTUN_LEGACY_ENCRYPT</c> = 999), which vtund resolves to
        /// <see cref="Blowfish128Ecb"/>.</summary>
        Legacy = 999,
    }
}
