using System.Text;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Noise;

namespace TqkLibrary.VpnClient.WireGuard.Handshake
{
    /// <summary>
    /// Computes and verifies the WireGuard <c>mac1</c> / <c>mac2</c> fields that armour every handshake message
    /// (whitepaper §5.4.4 "Denial of Service Mitigation &amp; Cookies"). Both are keyed-BLAKE2s-128 MACs over the
    /// leading bytes of the datagram:
    /// <list type="bullet">
    /// <item><c>mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:mac1_offset])</c> — keyed by the hash
    /// of the <b>recipient</b>'s static public key, so it proves the sender knows who it is talking to and is cheap
    /// to verify on the receive path before any DH work.</item>
    /// <item><c>mac2 = MAC(cookie, msg[0:mac2_offset])</c> — keyed by a fresh cookie when the peer is under load and
    /// has issued one (else all-zero); the cookie ties the sender to its source address.</item>
    /// </list>
    /// One instance is bound to a single static public key (the recipient's) — build with
    /// <see cref="ForRecipient"/>. Reuses <see cref="Blake2s"/> (HASH) and <see cref="Blake2sKeyedMac"/> (MAC) from
    /// the F.4 primitive set; holds no mutable handshake state.
    /// </summary>
    public sealed class WireGuardMac
    {
        readonly IHashAlgo _hash;
        readonly byte[] _mac1Key;     // HASH(LABEL_MAC1 || recipient.static_public)
        readonly byte[] _cookieKey;   // HASH(LABEL_COOKIE || recipient.static_public)

        WireGuardMac(IHashAlgo hash, byte[] mac1Key, byte[] cookieKey)
        {
            _hash = hash;
            _mac1Key = mac1Key;
            _cookieKey = cookieKey;
        }

        /// <summary>
        /// Builds a MAC helper bound to <paramref name="recipientStaticPublic"/> — the static public key of the peer
        /// the messages are addressed to (its own key for the verify path, the remote's for the build path). Both the
        /// mac1 and cookie keys are pre-hashed once. <paramref name="hash"/> defaults to <see cref="Blake2s"/>.
        /// </summary>
        public static WireGuardMac ForRecipient(byte[] recipientStaticPublic, IHashAlgo? hash = null)
        {
            if (recipientStaticPublic is null) throw new ArgumentNullException(nameof(recipientStaticPublic));
            if (recipientStaticPublic.Length != WireGuardConstants.KeyLength)
                throw new ArgumentException($"Static public key must be {WireGuardConstants.KeyLength} bytes.", nameof(recipientStaticPublic));

            IHashAlgo h = hash ?? new Blake2s();
            byte[] mac1Key = HashLabel(h, WireGuardConstants.LabelMac1, recipientStaticPublic);
            byte[] cookieKey = HashLabel(h, WireGuardConstants.LabelCookie, recipientStaticPublic);
            return new WireGuardMac(h, mac1Key, cookieKey);
        }

        /// <summary>The cookie-encryption key <c>HASH(LABEL_COOKIE || static_public)</c> (32 bytes). Returns a copy.</summary>
        public byte[] CookieKey => (byte[])_cookieKey.Clone();

        /// <summary>
        /// Computes <c>mac1 = MAC(mac1Key, content)</c> into <paramref name="mac1"/> (16 bytes), where
        /// <paramref name="content"/> is the message bytes up to (not including) the mac1 field.
        /// </summary>
        public void ComputeMac1(ReadOnlySpan<byte> content, Span<byte> mac1)
        {
            if (mac1.Length != WireGuardConstants.MacLength)
                throw new ArgumentException($"mac1 must be {WireGuardConstants.MacLength} bytes.", nameof(mac1));
            Blake2sKeyedMac.ComputeMac(_mac1Key, content, mac1);
        }

        /// <summary>Returns a fresh 16-byte mac1 over <paramref name="content"/>.</summary>
        public byte[] ComputeMac1(ReadOnlySpan<byte> content)
        {
            byte[] mac1 = new byte[WireGuardConstants.MacLength];
            ComputeMac1(content, mac1);
            return mac1;
        }

        /// <summary>Constant-time check that <paramref name="received"/> equals <c>mac1</c> over <paramref name="content"/>.</summary>
        public bool VerifyMac1(ReadOnlySpan<byte> content, ReadOnlySpan<byte> received)
        {
            if (received.Length != WireGuardConstants.MacLength) return false;
            Span<byte> expected = stackalloc byte[WireGuardConstants.MacLength];
            ComputeMac1(content, expected);
            return CryptoBytes.FixedTimeEquals(expected, received);
        }

        /// <summary>
        /// Computes <c>mac2 = MAC(cookie, content)</c> into <paramref name="mac2"/> (16 bytes), where
        /// <paramref name="content"/> is the message bytes up to (not including) the mac2 field — i.e. everything
        /// including mac1. The cookie is the 16-byte value learnt from a cookie-reply.
        /// </summary>
        public void ComputeMac2(ReadOnlySpan<byte> cookie, ReadOnlySpan<byte> content, Span<byte> mac2)
        {
            if (cookie.Length != WireGuardConstants.MacLength)
                throw new ArgumentException($"cookie must be {WireGuardConstants.MacLength} bytes.", nameof(cookie));
            if (mac2.Length != WireGuardConstants.MacLength)
                throw new ArgumentException($"mac2 must be {WireGuardConstants.MacLength} bytes.", nameof(mac2));
            Blake2sKeyedMac.ComputeMac(cookie, content, mac2);
        }

        /// <summary>Returns a fresh 16-byte mac2 over <paramref name="content"/> under <paramref name="cookie"/>.</summary>
        public byte[] ComputeMac2(ReadOnlySpan<byte> cookie, ReadOnlySpan<byte> content)
        {
            byte[] mac2 = new byte[WireGuardConstants.MacLength];
            ComputeMac2(cookie, content, mac2);
            return mac2;
        }

        /// <summary>Constant-time check that <paramref name="received"/> equals <c>mac2</c> over <paramref name="content"/>.</summary>
        public bool VerifyMac2(ReadOnlySpan<byte> cookie, ReadOnlySpan<byte> content, ReadOnlySpan<byte> received)
        {
            if (received.Length != WireGuardConstants.MacLength) return false;
            Span<byte> expected = stackalloc byte[WireGuardConstants.MacLength];
            ComputeMac2(cookie, content, expected);
            return CryptoBytes.FixedTimeEquals(expected, received);
        }

        // HASH(label || publicKey) using the running BLAKE2s digest — 8-byte ASCII label then the 32-byte key.
        static byte[] HashLabel(IHashAlgo hash, string label, byte[] publicKey)
        {
            byte[] labelBytes = Encoding.ASCII.GetBytes(label);
            byte[] input = new byte[labelBytes.Length + publicKey.Length];
            Buffer.BlockCopy(labelBytes, 0, input, 0, labelBytes.Length);
            Buffer.BlockCopy(publicKey, 0, input, labelBytes.Length, publicKey.Length);
            byte[] output = new byte[hash.HashSizeInBytes];
            hash.ComputeHash(input, output);
            return output;
        }
    }
}
