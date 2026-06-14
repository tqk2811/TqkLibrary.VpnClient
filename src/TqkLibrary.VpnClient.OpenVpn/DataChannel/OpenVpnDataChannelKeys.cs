namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// The per-direction symmetric key material the AEAD data channel runs on, derived from key-method-2
    /// (see <see cref="OpenVpnKeyMethod2.DeriveDataKeys"/>). For AES-256-GCM each direction needs a 32-byte cipher key
    /// and an 8-byte implicit IV (the high 8 bytes of the 12-byte nonce; the low 4 are the per-packet id). The send
    /// side of one peer equals the receive side of the other.
    /// </summary>
    public sealed class OpenVpnDataChannelKeys
    {
        /// <summary>AES-256 cipher key size.</summary>
        public const int CipherKeySize = 32;

        /// <summary>Implicit IV size = AEAD nonce (12) − packet-id (4).</summary>
        public const int ImplicitIvSize = 8;

        /// <summary>Creates the key material from its four parts.</summary>
        public OpenVpnDataChannelKeys(byte[] sendCipherKey, byte[] sendImplicitIv, byte[] receiveCipherKey, byte[] receiveImplicitIv)
        {
            SendCipherKey = sendCipherKey;
            SendImplicitIv = sendImplicitIv;
            ReceiveCipherKey = receiveCipherKey;
            ReceiveImplicitIv = receiveImplicitIv;
        }

        /// <summary>The 32-byte key encrypting our outgoing data packets.</summary>
        public byte[] SendCipherKey { get; }

        /// <summary>The 8-byte implicit IV for outgoing packets.</summary>
        public byte[] SendImplicitIv { get; }

        /// <summary>The 32-byte key decrypting the peer's data packets.</summary>
        public byte[] ReceiveCipherKey { get; }

        /// <summary>The 8-byte implicit IV for incoming packets.</summary>
        public byte[] ReceiveImplicitIv { get; }
    }
}
