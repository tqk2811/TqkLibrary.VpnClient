using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Aead;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;

namespace TqkLibrary.VpnClient.WireGuard.Handshake
{
    /// <summary>
    /// The WireGuard cookie machinery (whitepaper §5.4.7) — the DoS mitigation layered on top of mac1. When a peer is
    /// under load it answers a handshake message with a <b>cookie-reply</b> (type 3) instead of doing the expensive
    /// DH: the reply carries a 16-byte cookie sealed with XChaCha20-Poly1305. The sender decrypts the cookie and
    /// keys <c>mac2</c> with it on its next attempt, proving it can receive at its claimed source address.
    /// <para>
    /// The cookie itself is <c>MAC(changing_secret, source_address)</c> — a keyed-BLAKE2s-128 the responder can
    /// recompute statelessly from a periodically-rotated secret. The cookie-reply AEAD key is
    /// <c>HASH(LABEL_COOKIE || responder.static_public)</c> (shared by both sides via <see cref="WireGuardMac.CookieKey"/>)
    /// and its associated data is the <c>mac1</c> of the triggering message, so a reply only works for the exact
    /// message it answers. Reuses <see cref="XChaCha20Poly1305Cipher"/> and <see cref="Blake2sKeyedMac"/>.
    /// </para>
    /// </summary>
    public sealed class WireGuardCookie
    {
        const int CookieLength = WireGuardConstants.MacLength;     // 16
        const int NonceLength = 24;                                // XChaCha20-Poly1305 nonce
        const int TagLength = WireGuardConstants.TagLength;        // 16

        readonly IAeadCipher _xaead;
        readonly Func<int, byte[]> _randomNonce;

        /// <summary>
        /// Creates the cookie helper. <paramref name="xaead"/> defaults to <see cref="XChaCha20Poly1305Cipher"/>
        /// (24-byte nonce, 16-byte tag). <paramref name="randomNonce"/> supplies the cookie-reply nonce — defaults to
        /// a cryptographic RNG; tests can inject a deterministic one.
        /// </summary>
        public WireGuardCookie(IAeadCipher? xaead = null, Func<int, byte[]>? randomNonce = null)
        {
            _xaead = xaead ?? new XChaCha20Poly1305Cipher();
            if (_xaead.NonceSizeInBytes != NonceLength || _xaead.TagSizeInBytes != TagLength)
                throw new ArgumentException("Cookie reply requires XChaCha20-Poly1305 (nonce 24, tag 16).", nameof(xaead));
            _randomNonce = randomNonce ?? DefaultRandomNonce;
        }

        /// <summary>
        /// Computes the stateless cookie a loaded responder issues for a peer: <c>MAC(changingSecret, sourceAddress)</c>
        /// (keyed-BLAKE2s-128, 16 bytes). <paramref name="changingSecret"/> is the responder's periodically-rotated
        /// secret; <paramref name="sourceAddress"/> is the peer's UDP source address (IP + port), the value the
        /// cookie binds the sender to.
        /// </summary>
        public byte[] ComputeCookie(ReadOnlySpan<byte> changingSecret, ReadOnlySpan<byte> sourceAddress)
        {
            byte[] cookie = new byte[CookieLength];
            Blake2sKeyedMac.ComputeMac(changingSecret, sourceAddress, cookie);
            return cookie;
        }

        /// <summary>
        /// <b>Responder</b> — seals <paramref name="cookie"/> into a cookie-reply for the message identified by
        /// <paramref name="receiverIndex"/> (its sender index). <paramref name="cookieKey"/> is
        /// <c>HASH(LABEL_COOKIE || responder.static_public)</c> (<see cref="WireGuardMac.CookieKey"/>);
        /// <paramref name="triggeringMac1"/> is the mac1 of the message being answered (used as AEAD associated data).
        /// </summary>
        public WireGuardCookieReplyMessage CreateReply(uint receiverIndex, ReadOnlySpan<byte> cookie, ReadOnlySpan<byte> cookieKey, ReadOnlySpan<byte> triggeringMac1)
        {
            if (cookie.Length != CookieLength) throw new ArgumentException($"cookie must be {CookieLength} bytes.", nameof(cookie));
            if (cookieKey.Length != WireGuardConstants.KeyLength) throw new ArgumentException("cookieKey must be 32 bytes.", nameof(cookieKey));
            if (triggeringMac1.Length != WireGuardConstants.MacLength) throw new ArgumentException("triggeringMac1 must be 16 bytes.", nameof(triggeringMac1));

            byte[] nonce = _randomNonce(NonceLength);
            if (nonce is null || nonce.Length != NonceLength) throw new InvalidOperationException("nonce factory must return 24 bytes.");

            byte[] sealedCookie = new byte[CookieLength + TagLength];
            _xaead.Seal(cookieKey, nonce, cookie, triggeringMac1, sealedCookie.AsSpan(0, CookieLength), sealedCookie.AsSpan(CookieLength, TagLength));

            return new WireGuardCookieReplyMessage
            {
                ReceiverIndex = receiverIndex,
                Nonce = nonce,
                EncryptedCookie = sealedCookie,
            };
        }

        /// <summary>
        /// <b>Initiator</b> — opens a cookie-reply, returning the 16-byte cookie to key the next <c>mac2</c>.
        /// <paramref name="cookieKey"/> is <c>HASH(LABEL_COOKIE || responder.static_public)</c>;
        /// <paramref name="sentMac1"/> is the mac1 the initiator put on the message that prompted the reply (the
        /// AEAD associated data). Returns <c>false</c> (no cookie) if the tag fails to authenticate — a forged reply,
        /// or one for a different message.
        /// </summary>
        public bool TryReadCookie(WireGuardCookieReplyMessage reply, ReadOnlySpan<byte> cookieKey, ReadOnlySpan<byte> sentMac1, out byte[] cookie)
        {
            if (reply is null) throw new ArgumentNullException(nameof(reply));
            if (cookieKey.Length != WireGuardConstants.KeyLength) throw new ArgumentException("cookieKey must be 32 bytes.", nameof(cookieKey));
            if (sentMac1.Length != WireGuardConstants.MacLength) throw new ArgumentException("sentMac1 must be 16 bytes.", nameof(sentMac1));

            cookie = Array.Empty<byte>();
            if (reply.Nonce is null || reply.Nonce.Length != NonceLength) return false;
            if (reply.EncryptedCookie is null || reply.EncryptedCookie.Length != CookieLength + TagLength) return false;

            byte[] opened = new byte[CookieLength];
            bool ok = _xaead.Open(
                cookieKey,
                reply.Nonce,
                reply.EncryptedCookie.AsSpan(0, CookieLength),
                reply.EncryptedCookie.AsSpan(CookieLength, TagLength),
                sentMac1,
                opened);
            if (!ok) return false;

            cookie = opened;
            return true;
        }

        static byte[] DefaultRandomNonce(int length)
        {
            byte[] nonce = new byte[length];
#if NET6_0_OR_GREATER
            System.Security.Cryptography.RandomNumberGenerator.Fill(nonce);
#else
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(nonce);
#endif
            return nonce;
        }
    }
}
