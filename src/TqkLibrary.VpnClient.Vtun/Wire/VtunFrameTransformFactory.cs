using TqkLibrary.VpnClient.Vtun.Wire.Enums;
using TqkLibrary.VpnClient.Vtun.Wire.Interfaces;

namespace TqkLibrary.VpnClient.Vtun.Wire
{
    /// <summary>
    /// Resolves the data-plane <see cref="IVtunFrameTransform"/> for the cipher the server selected (the <c>E&lt;n&gt;</c>
    /// id in the host-flags string, parsed into a <see cref="VtunCipher"/>). Only the modes this driver implements return
    /// a transform; an unsupported but recognised cipher returns <c>null</c> via <see cref="TryCreate"/> so the caller can
    /// name it in a clear error.
    /// <para>Today only the vtun default — <see cref="VtunCipher.Blowfish128Ecb"/> (and the legacy bare-<c>E</c> alias
    /// <see cref="VtunCipher.Legacy"/>, which vtund resolves to the same cipher) — is supported. The other ids exist on
    /// <see cref="VtunCipher"/> for precise diagnostics and to leave room for CBC/CFB/OFB and AES later.</para>
    /// </summary>
    public static class VtunFrameTransformFactory
    {
        /// <summary>
        /// Returns the transform for <paramref name="cipher"/> keyed from <paramref name="password"/>, or <c>null</c> if
        /// the cipher is recognised but not yet implemented by this driver.
        /// </summary>
        public static IVtunFrameTransform? TryCreate(VtunCipher cipher, string password) => cipher switch
        {
            // vtund's `encrypt yes` default and the legacy bare-`E` token both run Blowfish-128-ECB.
            VtunCipher.Blowfish128Ecb or VtunCipher.Legacy => new VtunBlowfishEcbTransform(password),
            _ => null,
        };

        /// <summary>
        /// Maps a parsed <c>E&lt;n&gt;</c> cipher id to a <see cref="VtunCipher"/>. <c>0</c> is the legacy bare-<c>E</c>
        /// (vtund's <c>VTUN_LEGACY_ENCRYPT</c>); any other value is taken as the literal <c>VTUN_ENC_*</c> id.
        /// </summary>
        public static VtunCipher FromCipherId(int cipherId)
            => cipherId == 0 ? VtunCipher.Legacy : (VtunCipher)cipherId;
    }
}
