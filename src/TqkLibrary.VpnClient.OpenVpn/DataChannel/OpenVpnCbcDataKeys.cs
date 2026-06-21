namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// The per-direction key material for the non-AEAD CBC data channel (<see cref="OpenVpnCbcDataChannel"/>), sliced
    /// from key-method-2's key2. Unlike the AEAD keys (a cipher key + an implicit IV), CBC needs a cipher key (for
    /// AES-CBC, with a random per-packet IV) plus a separate HMAC key (for the <c>--auth</c> packet MAC). The send side
    /// of one peer equals the receive side of the other.
    /// </summary>
    public sealed class OpenVpnCbcDataKeys
    {
        /// <summary>Creates the key material from its four parts.</summary>
        public OpenVpnCbcDataKeys(byte[] sendCipherKey, byte[] sendHmacKey, byte[] receiveCipherKey, byte[] receiveHmacKey)
        {
            SendCipherKey = sendCipherKey ?? throw new ArgumentNullException(nameof(sendCipherKey));
            SendHmacKey = sendHmacKey ?? throw new ArgumentNullException(nameof(sendHmacKey));
            ReceiveCipherKey = receiveCipherKey ?? throw new ArgumentNullException(nameof(receiveCipherKey));
            ReceiveHmacKey = receiveHmacKey ?? throw new ArgumentNullException(nameof(receiveHmacKey));
        }

        /// <summary>The AES-CBC key encrypting our outgoing data packets.</summary>
        public byte[] SendCipherKey { get; }

        /// <summary>The HMAC key authenticating our outgoing data packets.</summary>
        public byte[] SendHmacKey { get; }

        /// <summary>The AES-CBC key decrypting the peer's data packets.</summary>
        public byte[] ReceiveCipherKey { get; }

        /// <summary>The HMAC key verifying the peer's data packets.</summary>
        public byte[] ReceiveHmacKey { get; }
    }
}
