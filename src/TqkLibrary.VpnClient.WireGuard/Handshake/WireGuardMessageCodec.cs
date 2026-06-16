using System.Buffers.Binary;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;

namespace TqkLibrary.VpnClient.WireGuard.Handshake
{
    /// <summary>
    /// Serialises and parses the two WireGuard handshake messages byte-for-byte (whitepaper §5.4.2/§5.4.3). All
    /// multi-byte scalars (the type word and the session indices) are <b>little-endian</b>; the type byte is
    /// followed by three reserved zero bytes. The codec only moves bytes — it does not touch the crypto state
    /// (<see cref="WireGuardHandshake"/> fills the encrypted fields) nor mac1/mac2 (filled by the V3.c machinery),
    /// so the trailing 32 mac bytes round-trip verbatim.
    /// </summary>
    public sealed class WireGuardMessageCodec
    {
        // ---- Type-1 initiation field offsets (148 bytes total) ----
        const int InitTypeOffset = 0;                                              // 1 byte type + 3 reserved
        const int InitSenderOffset = 4;                                            // 4
        const int InitEphemeralOffset = InitSenderOffset + WireGuardConstants.IndexLength;   // 8
        const int InitStaticOffset = InitEphemeralOffset + WireGuardConstants.KeyLength;     // 40
        const int InitStaticLength = WireGuardConstants.KeyLength + WireGuardConstants.TagLength;        // 48
        const int InitTimestampOffset = InitStaticOffset + InitStaticLength;                 // 88
        const int InitTimestampLength = WireGuardConstants.TimestampLength + WireGuardConstants.TagLength; // 28
        const int InitMac1Offset = InitTimestampOffset + InitTimestampLength;                // 116
        const int InitMac2Offset = InitMac1Offset + WireGuardConstants.MacLength;            // 132

        // ---- Type-2 response field offsets (92 bytes total) ----
        const int RespTypeOffset = 0;                                              // 1 byte type + 3 reserved
        const int RespSenderOffset = 4;                                            // 4
        const int RespReceiverOffset = RespSenderOffset + WireGuardConstants.IndexLength;    // 8
        const int RespEphemeralOffset = RespReceiverOffset + WireGuardConstants.IndexLength; // 12
        const int RespEmptyOffset = RespEphemeralOffset + WireGuardConstants.KeyLength;      // 44
        const int RespEmptyLength = WireGuardConstants.TagLength;                            // 16 (empty payload → tag only)
        const int RespMac1Offset = RespEmptyOffset + RespEmptyLength;                        // 60
        const int RespMac2Offset = RespMac1Offset + WireGuardConstants.MacLength;            // 76

        // ---- Type-3 cookie-reply field offsets (64 bytes total) ----
        // type(1) | reserved(3) | receiver(4) | nonce(24) | encrypted_cookie(16+16)
        const int CookieTypeOffset = 0;                                            // 1 byte type + 3 reserved
        const int CookieReceiverOffset = 4;                                        // 4
        const int CookieNonceOffset = CookieReceiverOffset + WireGuardConstants.IndexLength; // 8
        const int CookieNonceLength = 24;                                          // XChaCha20-Poly1305 nonce
        const int CookieEncryptedOffset = CookieNonceOffset + CookieNonceLength;             // 32
        const int CookieEncryptedLength = WireGuardConstants.MacLength + WireGuardConstants.TagLength; // 32

        /// <summary>Total length of a type-3 cookie-reply message (64 bytes).</summary>
        public const int CookieReplyMessageLength = CookieEncryptedOffset + CookieEncryptedLength;

        /// <summary>
        /// The portion of an initiation message covered by mac1 — everything before the mac1 field (offset 0..115).
        /// V3.c keys BLAKE2s over this span.
        /// </summary>
        public const int InitiationMaccedLength = InitMac1Offset;

        /// <summary>The portion of a response message covered by mac1 — everything before the mac1 field (offset 0..59).</summary>
        public const int ResponseMaccedLength = RespMac1Offset;

        /// <summary>Encodes <paramref name="message"/> as a fresh 148-byte type-1 initiation datagram.</summary>
        public byte[] EncodeInitiation(WireGuardInitiationMessage message)
        {
            ValidateField(message.UnencryptedEphemeral, WireGuardConstants.KeyLength, nameof(message.UnencryptedEphemeral));
            ValidateField(message.EncryptedStatic, InitStaticLength, nameof(message.EncryptedStatic));
            ValidateField(message.EncryptedTimestamp, InitTimestampLength, nameof(message.EncryptedTimestamp));
            ValidateField(message.Mac1, WireGuardConstants.MacLength, nameof(message.Mac1));
            ValidateField(message.Mac2, WireGuardConstants.MacLength, nameof(message.Mac2));

            byte[] buffer = new byte[WireGuardConstants.InitiationMessageLength];
            buffer[InitTypeOffset] = WireGuardConstants.MessageTypeInitiation; // next 3 bytes stay zero (reserved)
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(InitSenderOffset, 4), message.SenderIndex);
            message.UnencryptedEphemeral.CopyTo(buffer.AsSpan(InitEphemeralOffset));
            message.EncryptedStatic.CopyTo(buffer.AsSpan(InitStaticOffset));
            message.EncryptedTimestamp.CopyTo(buffer.AsSpan(InitTimestampOffset));
            message.Mac1.CopyTo(buffer.AsSpan(InitMac1Offset));
            message.Mac2.CopyTo(buffer.AsSpan(InitMac2Offset));
            return buffer;
        }

        /// <summary>
        /// Parses a 148-byte type-1 initiation datagram. Returns <c>false</c> (no exception) when the length or the
        /// type/reserved bytes are wrong, so a malformed/foreign datagram is simply dropped.
        /// </summary>
        public bool TryDecodeInitiation(ReadOnlySpan<byte> datagram, out WireGuardInitiationMessage message)
        {
            message = null!;
            if (datagram.Length != WireGuardConstants.InitiationMessageLength) return false;
            if (datagram[InitTypeOffset] != WireGuardConstants.MessageTypeInitiation) return false;
            if (datagram[1] != 0 || datagram[2] != 0 || datagram[3] != 0) return false;

            message = new WireGuardInitiationMessage
            {
                SenderIndex = BinaryPrimitives.ReadUInt32LittleEndian(datagram.Slice(InitSenderOffset, 4)),
                UnencryptedEphemeral = datagram.Slice(InitEphemeralOffset, WireGuardConstants.KeyLength).ToArray(),
                EncryptedStatic = datagram.Slice(InitStaticOffset, InitStaticLength).ToArray(),
                EncryptedTimestamp = datagram.Slice(InitTimestampOffset, InitTimestampLength).ToArray(),
                Mac1 = datagram.Slice(InitMac1Offset, WireGuardConstants.MacLength).ToArray(),
                Mac2 = datagram.Slice(InitMac2Offset, WireGuardConstants.MacLength).ToArray(),
            };
            return true;
        }

        /// <summary>Encodes <paramref name="message"/> as a fresh 92-byte type-2 response datagram.</summary>
        public byte[] EncodeResponse(WireGuardResponseMessage message)
        {
            ValidateField(message.UnencryptedEphemeral, WireGuardConstants.KeyLength, nameof(message.UnencryptedEphemeral));
            ValidateField(message.EncryptedNothing, RespEmptyLength, nameof(message.EncryptedNothing));
            ValidateField(message.Mac1, WireGuardConstants.MacLength, nameof(message.Mac1));
            ValidateField(message.Mac2, WireGuardConstants.MacLength, nameof(message.Mac2));

            byte[] buffer = new byte[WireGuardConstants.ResponseMessageLength];
            buffer[RespTypeOffset] = WireGuardConstants.MessageTypeResponse; // next 3 bytes stay zero (reserved)
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(RespSenderOffset, 4), message.SenderIndex);
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(RespReceiverOffset, 4), message.ReceiverIndex);
            message.UnencryptedEphemeral.CopyTo(buffer.AsSpan(RespEphemeralOffset));
            message.EncryptedNothing.CopyTo(buffer.AsSpan(RespEmptyOffset));
            message.Mac1.CopyTo(buffer.AsSpan(RespMac1Offset));
            message.Mac2.CopyTo(buffer.AsSpan(RespMac2Offset));
            return buffer;
        }

        /// <summary>
        /// Parses a 92-byte type-2 response datagram. Returns <c>false</c> (no exception) when the length or the
        /// type/reserved bytes are wrong.
        /// </summary>
        public bool TryDecodeResponse(ReadOnlySpan<byte> datagram, out WireGuardResponseMessage message)
        {
            message = null!;
            if (datagram.Length != WireGuardConstants.ResponseMessageLength) return false;
            if (datagram[RespTypeOffset] != WireGuardConstants.MessageTypeResponse) return false;
            if (datagram[1] != 0 || datagram[2] != 0 || datagram[3] != 0) return false;

            message = new WireGuardResponseMessage
            {
                SenderIndex = BinaryPrimitives.ReadUInt32LittleEndian(datagram.Slice(RespSenderOffset, 4)),
                ReceiverIndex = BinaryPrimitives.ReadUInt32LittleEndian(datagram.Slice(RespReceiverOffset, 4)),
                UnencryptedEphemeral = datagram.Slice(RespEphemeralOffset, WireGuardConstants.KeyLength).ToArray(),
                EncryptedNothing = datagram.Slice(RespEmptyOffset, RespEmptyLength).ToArray(),
                Mac1 = datagram.Slice(RespMac1Offset, WireGuardConstants.MacLength).ToArray(),
                Mac2 = datagram.Slice(RespMac2Offset, WireGuardConstants.MacLength).ToArray(),
            };
            return true;
        }

        // ---- Cookie-reply (type 3) ----

        /// <summary>Encodes <paramref name="message"/> as a fresh 64-byte type-3 cookie-reply datagram.</summary>
        public byte[] EncodeCookieReply(WireGuardCookieReplyMessage message)
        {
            if (message is null) throw new ArgumentNullException(nameof(message));
            ValidateField(message.Nonce, CookieNonceLength, nameof(message.Nonce));
            ValidateField(message.EncryptedCookie, CookieEncryptedLength, nameof(message.EncryptedCookie));

            byte[] buffer = new byte[CookieReplyMessageLength];
            buffer[CookieTypeOffset] = WireGuardConstants.MessageTypeCookieReply; // next 3 bytes stay zero (reserved)
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(CookieReceiverOffset, 4), message.ReceiverIndex);
            message.Nonce.CopyTo(buffer.AsSpan(CookieNonceOffset));
            message.EncryptedCookie.CopyTo(buffer.AsSpan(CookieEncryptedOffset));
            return buffer;
        }

        /// <summary>
        /// Parses a 64-byte type-3 cookie-reply datagram. Returns <c>false</c> (no exception) when the length or the
        /// type/reserved bytes are wrong.
        /// </summary>
        public bool TryDecodeCookieReply(ReadOnlySpan<byte> datagram, out WireGuardCookieReplyMessage message)
        {
            message = null!;
            if (datagram.Length != CookieReplyMessageLength) return false;
            if (datagram[CookieTypeOffset] != WireGuardConstants.MessageTypeCookieReply) return false;
            if (datagram[1] != 0 || datagram[2] != 0 || datagram[3] != 0) return false;

            message = new WireGuardCookieReplyMessage
            {
                ReceiverIndex = BinaryPrimitives.ReadUInt32LittleEndian(datagram.Slice(CookieReceiverOffset, 4)),
                Nonce = datagram.Slice(CookieNonceOffset, CookieNonceLength).ToArray(),
                EncryptedCookie = datagram.Slice(CookieEncryptedOffset, CookieEncryptedLength).ToArray(),
            };
            return true;
        }

        // ---- In-place mac1/mac2 on an encoded datagram (whitepaper §5.4.4) ----
        //
        // The macs cover the *serialised* leading bytes, so the simplest correct flow is: encode the message with
        // zero macs, then stamp mac1/mac2 over the buffer. mac1 keys over msg[0:mac1_offset]; mac2 keys over
        // msg[0:mac2_offset] (which includes mac1). The two message types share the same trailing 32-byte mac block,
        // and mac1 always sits 32 bytes before the end, mac2 16 bytes before — so the offsets are derivable from the
        // datagram length, letting one helper serve both type-1 and type-2 wires.

        /// <summary>
        /// Stamps <c>mac1</c> (and, when a cookie is supplied, <c>mac2</c>) into an already-encoded type-1 or type-2
        /// <paramref name="datagram"/> using <paramref name="mac"/> bound to the recipient's static key. mac1 is
        /// computed over the bytes preceding the mac1 field; mac2 over the bytes preceding the mac2 field (i.e.
        /// including mac1). Pass <paramref name="cookie"/> <c>null</c> to leave mac2 all-zero (no cookie yet).
        /// </summary>
        public void ApplyMacs(Span<byte> datagram, WireGuardMac mac, byte[]? cookie = null)
        {
            if (mac is null) throw new ArgumentNullException(nameof(mac));
            int mac2Offset = datagram.Length - WireGuardConstants.MacLength;
            int mac1Offset = mac2Offset - WireGuardConstants.MacLength;
            if (mac1Offset < 0) throw new ArgumentException("datagram too small to carry mac1/mac2.", nameof(datagram));

            mac.ComputeMac1(datagram.Slice(0, mac1Offset), datagram.Slice(mac1Offset, WireGuardConstants.MacLength));

            Span<byte> mac2 = datagram.Slice(mac2Offset, WireGuardConstants.MacLength);
            if (cookie is null)
                mac2.Clear();
            else
                mac.ComputeMac2(cookie, datagram.Slice(0, mac2Offset), mac2);
        }

        /// <summary>
        /// Verifies the <c>mac1</c> of a received type-1 or type-2 <paramref name="datagram"/> against
        /// <paramref name="mac"/> bound to <b>our own</b> static key (the recipient). Returns <c>false</c> so a
        /// forged/foreign datagram is dropped before any DH work. Does not check mac2 (that is the cookie path).
        /// </summary>
        public bool VerifyMac1(ReadOnlySpan<byte> datagram, WireGuardMac mac)
        {
            if (mac is null) throw new ArgumentNullException(nameof(mac));
            int mac2Offset = datagram.Length - WireGuardConstants.MacLength;
            int mac1Offset = mac2Offset - WireGuardConstants.MacLength;
            if (mac1Offset < 0) return false;
            return mac.VerifyMac1(datagram.Slice(0, mac1Offset), datagram.Slice(mac1Offset, WireGuardConstants.MacLength));
        }

        /// <summary>
        /// Reads the <c>mac1</c> field out of an encoded type-1 or type-2 <paramref name="datagram"/> (the 16 bytes
        /// 32 from the end) — the associated data the cookie-reply binds to.
        /// </summary>
        public byte[] ReadMac1(ReadOnlySpan<byte> datagram)
        {
            int mac1Offset = datagram.Length - 2 * WireGuardConstants.MacLength;
            if (mac1Offset < 0) throw new ArgumentException("datagram too small to carry mac1.", nameof(datagram));
            return datagram.Slice(mac1Offset, WireGuardConstants.MacLength).ToArray();
        }

        static void ValidateField(byte[] field, int expected, string name)
        {
            if (field is null) throw new ArgumentNullException(name);
            if (field.Length != expected) throw new ArgumentException($"{name} must be {expected} bytes (got {field.Length}).", name);
        }
    }
}
