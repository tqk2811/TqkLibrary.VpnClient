using TqkLibrary.VpnClient.Drivers.Ayiya.Enums;

namespace TqkLibrary.VpnClient.Drivers.Ayiya
{
    /// <summary>
    /// The structural result of parsing an AYIYA datagram (<see cref="AyiyaPacket.TryParse"/>): every header field plus the
    /// byte offsets/lengths of the identity, signature and payload sections. Carries no crypto verdict — signature
    /// verification is <see cref="AyiyaPacket.VerifySignature"/>. A value type (no allocation on the parse hot path).
    /// </summary>
    public readonly struct AyiyaHeader
    {
        /// <summary>Creates a header value. Normally produced by <see cref="AyiyaPacket.TryParse"/>.</summary>
        public AyiyaHeader(byte idLen, AyiyaIdType idType, byte sigLenWords, AyiyaHashMethod hashMethod,
            AyiyaAuthMethod authMethod, AyiyaOpcode opcode, byte nextHeader, uint epochTime,
            int identityOffset, int identityLength, int signatureOffset, int signatureLength,
            int payloadOffset, int payloadLength)
        {
            IdLen = idLen;
            IdType = idType;
            SigLenWords = sigLenWords;
            HashMethod = hashMethod;
            AuthMethod = authMethod;
            Opcode = opcode;
            NextHeader = nextHeader;
            EpochTime = epochTime;
            IdentityOffset = identityOffset;
            IdentityLength = identityLength;
            SignatureOffset = signatureOffset;
            SignatureLength = signatureLength;
            PayloadOffset = payloadOffset;
            PayloadLength = payloadLength;
        }

        /// <summary>The raw idlen nibble (high nibble of byte 0). The identity is <c>2^IdLen</c> bytes long.</summary>
        public byte IdLen { get; }

        /// <summary>The identity type (low nibble of byte 0).</summary>
        public AyiyaIdType IdType { get; }

        /// <summary>The raw siglen nibble (high nibble of byte 1), counted in 32-bit words. The signature is <c>SigLenWords*4</c> bytes.</summary>
        public byte SigLenWords { get; }

        /// <summary>The hash method (low nibble of byte 1).</summary>
        public AyiyaHashMethod HashMethod { get; }

        /// <summary>The authentication method (high nibble of byte 2).</summary>
        public AyiyaAuthMethod AuthMethod { get; }

        /// <summary>The opcode (low nibble of byte 2).</summary>
        public AyiyaOpcode Opcode { get; }

        /// <summary>The next-header / inner IP protocol number (byte 3): 41 = IPv6, 59 = no-next-header (heartbeat).</summary>
        public byte NextHeader { get; }

        /// <summary>The epoch time (seconds since 1970-01-01 UTC, big-endian uint32 at bytes 4..8) — the replay guard.</summary>
        public uint EpochTime { get; }

        /// <summary>Byte offset of the identity field (always 8 — after the 4-byte header + 4-byte epoch).</summary>
        public int IdentityOffset { get; }

        /// <summary>Identity length in bytes (<c>2^IdLen</c>).</summary>
        public int IdentityLength { get; }

        /// <summary>Byte offset of the signature field.</summary>
        public int SignatureOffset { get; }

        /// <summary>Signature length in bytes (<c>SigLenWords*4</c>).</summary>
        public int SignatureLength { get; }

        /// <summary>Byte offset at which the payload begins (end of the header). May equal the datagram length (empty payload).</summary>
        public int PayloadOffset { get; }

        /// <summary>Payload length in bytes (datagram length minus <see cref="PayloadOffset"/>).</summary>
        public int PayloadLength { get; }
    }
}
