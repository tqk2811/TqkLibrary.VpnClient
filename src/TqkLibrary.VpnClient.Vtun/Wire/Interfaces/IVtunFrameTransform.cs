namespace TqkLibrary.VpnClient.Vtun.Wire.Interfaces
{
    /// <summary>
    /// Transforms a single vtun data-frame payload on the data plane — the hook vtund's <c>encrypt_buf</c> /
    /// <c>decrypt_buf</c> (the <c>lfd_encrypt</c> module) occupies. It runs <b>after</b> compression and <b>before</b> the
    /// 2-byte length+flags frame header on send, and the inverse on receive: the bytes a transform produces are exactly
    /// what travels inside one <see cref="VtunFrameType"/>.<c>Data</c> frame.
    /// <para>The no-encrypt path uses no transform at all (the bare tunnelled packet is the frame payload). A non-null
    /// transform is installed only when the server selects a supported <see cref="Enums.VtunCipher"/>.</para>
    /// </summary>
    public interface IVtunFrameTransform
    {
        /// <summary>
        /// Encrypts one outbound frame payload (a bare tunnelled packet), returning the bytes to place in the data frame.
        /// May grow the payload (padding); the result length must still fit a single vtun frame.
        /// </summary>
        byte[] Encrypt(ReadOnlySpan<byte> payload);

        /// <summary>
        /// Decrypts one inbound frame payload back to the bare tunnelled packet. Returns an empty array if the frame is
        /// malformed (bad padding / wrong length) so the caller can drop it without tearing the tunnel down.
        /// </summary>
        byte[] Decrypt(ReadOnlySpan<byte> frame);
    }
}
