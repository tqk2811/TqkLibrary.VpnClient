using TqkLibrary.VpnClient.Crypto.Noise;

namespace TqkLibrary.VpnClient.WireGuard
{
    /// <summary>
    /// Protocol constants for the WireGuard handshake (whitepaper "WireGuard: Next Generation Kernel Network Tunnel",
    /// §5.4 "Messages"). Holds the four hashed labels — <c>CONSTRUCTION</c>, <c>IDENTIFIER</c>, <c>LABEL_MAC1</c>,
    /// <c>LABEL_COOKIE</c> — plus the fixed sizes and field offsets of the type-1 initiation and type-2 response
    /// messages so the codec (<see cref="Handshake.WireGuardMessageCodec"/>) can build/parse them byte-for-byte.
    /// <para>
    /// <see cref="Construction"/> / <see cref="Identifier"/> are re-exported from
    /// <see cref="NoiseSymmetricState"/> (the single source of truth, used to seed the symmetric state) so the two
    /// can never drift; <see cref="LabelMac1"/> / <see cref="LabelCookie"/> are only used by the mac1/mac2 +
    /// cookie machinery (V3.c) and are defined here ahead of that work.
    /// </para>
    /// </summary>
    public static class WireGuardConstants
    {
        /// <summary>Handshake construction string: <c>"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"</c> as named in the WireGuard
        /// whitepaper. The concrete Noise implementation uses the fully-spelt cipher name
        /// (<see cref="NoiseSymmetricState.Construction"/>, <c>ChaCha20Poly1305</c>) which is what actually seeds the
        /// chaining key — that constant is the authoritative one and what every interop test hashes.</summary>
        public const string Construction = NoiseSymmetricState.Construction;

        /// <summary>Identifier string mixed into the transcript hash right after construction:
        /// <c>"WireGuard v1 zx2c4 Jason@zx2c4.com"</c>.</summary>
        public const string Identifier = NoiseSymmetricState.Identifier;

        /// <summary>mac1 label, hashed with the recipient's static public key to key the first MAC (V3.c).</summary>
        public const string LabelMac1 = "mac1----";

        /// <summary>Cookie label, hashed with the recipient's static public key to encrypt the cookie reply (V3.c).</summary>
        public const string LabelCookie = "cookie--";

        // ---- Fixed primitive sizes (WireGuard pins all of these) ----

        /// <summary>X25519 public-key / private-key length, BLAKE2s digest length and chaining-key length.</summary>
        public const int KeyLength = 32;

        /// <summary>ChaCha20-Poly1305 authentication-tag length.</summary>
        public const int TagLength = 16;

        /// <summary>TAI64N timestamp length (8-byte seconds + 4-byte nanoseconds).</summary>
        public const int TimestampLength = 12;

        /// <summary>mac1 / mac2 length (keyed BLAKE2s truncated to 16 bytes).</summary>
        public const int MacLength = 16;

        /// <summary>Sender/receiver index length (32-bit little-endian).</summary>
        public const int IndexLength = 4;

        /// <summary>The WireGuard default tunnel MTU (1420 = 1500 − 60 IPv6 − 8 UDP − 32 transport header).</summary>
        public const int DefaultMtu = 1420;

        // ---- Message type discriminators (first byte) ----

        /// <summary>Handshake-initiation message type.</summary>
        public const byte MessageTypeInitiation = 1;

        /// <summary>Handshake-response message type.</summary>
        public const byte MessageTypeResponse = 2;

        /// <summary>Cookie-reply message type (V3.c).</summary>
        public const byte MessageTypeCookieReply = 3;

        /// <summary>Transport-data message type (V3.d).</summary>
        public const byte MessageTypeTransportData = 4;

        // ---- Initiation message layout (type 1, 148 bytes) ----
        // type(1) | reserved(3) | sender(4) | ephemeral(32) | enc_static(32+16) | enc_timestamp(12+16) | mac1(16) | mac2(16)

        /// <summary>Total length of a type-1 handshake-initiation message (148 bytes).</summary>
        public const int InitiationMessageLength =
            1 + 3 + IndexLength + KeyLength + (KeyLength + TagLength) + (TimestampLength + TagLength) + MacLength + MacLength;

        // ---- Response message layout (type 2, 92 bytes) ----
        // type(1) | reserved(3) | sender(4) | receiver(4) | ephemeral(32) | enc_empty(0+16) | mac1(16) | mac2(16)

        /// <summary>Total length of a type-2 handshake-response message (92 bytes).</summary>
        public const int ResponseMessageLength =
            1 + 3 + IndexLength + IndexLength + KeyLength + TagLength + MacLength + MacLength;
    }
}
