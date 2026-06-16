namespace TqkLibrary.VpnClient.WireGuard.Handshake.Models
{
    /// <summary>
    /// A decoded WireGuard cookie-reply message (type 3, whitepaper §5.4.7). Wire layout (64 bytes):
    /// <c>type(1) | reserved(3) | receiver(4) | nonce(24) | encrypted_cookie(16+16)</c>. The responder sends this
    /// when it is under load instead of a handshake response; it carries an XChaCha20-Poly1305-sealed 16-byte cookie
    /// the initiator must echo back as <c>mac2</c> on its next message. The AEAD's associated data is the
    /// <c>mac1</c> field of the message that triggered the reply, so the reply can only be used by the peer that
    /// sent that message.
    /// </summary>
    public sealed record WireGuardCookieReplyMessage
    {
        /// <summary>The index the cookie-reply is addressed to — echoes the sender index of the triggering message
        /// (little-endian on the wire) so the recipient can route it to the right session.</summary>
        public required uint ReceiverIndex { get; init; }

        /// <summary>The 24-byte XChaCha20-Poly1305 nonce chosen by the responder.</summary>
        public required byte[] Nonce { get; init; }

        /// <summary>The sealed cookie: 16 ciphertext bytes + a 16-byte tag = 32 bytes.</summary>
        public required byte[] EncryptedCookie { get; init; }
    }
}
