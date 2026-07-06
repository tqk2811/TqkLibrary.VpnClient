using System;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Drivers.Ayiya.Enums;

namespace TqkLibrary.VpnClient.Drivers.Ayiya
{
    /// <summary>
    /// Stateless codec for the AYIYA (Anything In Anything, draft-massar-v6ops-ayiya-02) datagram — a pure encode / parse /
    /// sign / verify pair holding no tunnel state. Layout:
    /// <list type="bullet">
    ///   <item>Byte 0 = <c>idlen(4) | idtype(4)</c> — identity length is <b>2^idlen</b> bytes; idtype 1=int/2=string/4=IPv4/6=IPv6.</item>
    ///   <item>Byte 1 = <c>siglen(4) | hshmeth(4)</c> — signature length is <b>siglen*4</b> bytes (= digest size); hshmeth 0=none/1=MD5/2=SHA1.</item>
    ///   <item>Byte 2 = <c>autmeth(4) | opcode(4)</c> — autmeth 0=none/1=shared-secret/2=PGP; opcode 1=forward, 2=echo-request…</item>
    ///   <item>Byte 3 = <c>nextheader</c> — the inner IP protocol: 41 = IPv6, 59 = no-next-header (heartbeat/echo, empty payload).</item>
    ///   <item>Bytes 4..8 = <c>epochtime</c> — big-endian uint32 seconds since 1970 (the replay guard).</item>
    ///   <item>Then <c>2^idlen</c> bytes identity, <c>siglen*4</c> bytes signature, then the payload.</item>
    /// </list>
    /// <para><b>Shared-secret SHA-1 signature (aiccu algorithm).</b> To sign: put <c>H(password)</c> (the digest of the
    /// shared secret) into the signature field, hash the <b>whole</b> datagram (header + epoch + identity + [H(password)]
    /// + payload), and overwrite the signature field with that hash. To verify: replace the received signature field with
    /// <c>H(password)</c>, re-hash the whole datagram, and constant-time-compare against the received signature. AYIYA
    /// signs integrity and guards replay by epoch time — it does <b>not</b> encrypt the payload.</para>
    /// </summary>
    public static class AyiyaPacket
    {
        /// <summary>The fixed 4-byte field header (bytes 0..4).</summary>
        public const int FixedHeaderLength = 4;

        /// <summary>The epoch-time field length in bytes (a big-endian uint32).</summary>
        public const int EpochTimeLength = 4;

        /// <summary>The header prefix before the identity: fixed header + epoch time (= 8 bytes).</summary>
        public const int HeaderPrefixLength = FixedHeaderLength + EpochTimeLength;

        /// <summary>The digest size (bytes) for a hash method: MD5 = 16, SHA-1 = 20, None = 0.</summary>
        public static int HashSize(AyiyaHashMethod method) => method switch
        {
            AyiyaHashMethod.Md5 => 16,
            AyiyaHashMethod.Sha1 => 20,
            _ => 0,
        };

        /// <summary>
        /// The <c>idlen</c> nibble for an identity of <paramref name="identityLength"/> bytes: the exponent <c>n</c> where
        /// <c>2^n == identityLength</c> (so an IPv6 identity of 16 bytes → 4). Throws <see cref="ArgumentException"/> when
        /// the length is not a power of two in the encodable range (1 … 2^15).
        /// </summary>
        public static int IdLenFor(int identityLength)
        {
            if (identityLength > 0 && identityLength <= (1 << 15))
            {
                for (int n = 0; n <= 15; n++)
                    if ((1 << n) == identityLength)
                        return n;
            }
            throw new ArgumentException(
                $"AYIYA identity length must be a power of two in 1..32768 (2^idlen); got {identityLength}.", nameof(identityLength));
        }

        /// <summary>Digests the shared secret (<paramref name="password"/>) with <paramref name="method"/> — the value placed into the signature field before signing.</summary>
        public static byte[] HashPassword(AyiyaHashMethod method, ReadOnlySpan<byte> password)
        {
            int size = HashSize(method);
            if (size == 0)
                throw new ArgumentException("AYIYA shared-secret authentication requires MD5 or SHA-1.", nameof(method));
            byte[] result = new byte[size];
            ComputeDigest(method, password, result);
            return result;
        }

        /// <summary>
        /// Encodes and signs one AYIYA datagram. <paramref name="secretHash"/> is <c>H(password)</c> (from
        /// <see cref="HashPassword"/>) — it is written into the signature field, then the whole datagram is hashed and the
        /// result overwrites the field. <paramref name="identity"/> length must be a power of two; <paramref name="payload"/>
        /// is the inner IPv6 packet (for <see cref="AyiyaOpcode.Forward"/> / next-header 41) or empty (heartbeat / next-header 59).
        /// </summary>
        public static byte[] Encode(AyiyaIdType idType, ReadOnlySpan<byte> identity, AyiyaHashMethod hashMethod,
            AyiyaAuthMethod authMethod, AyiyaOpcode opcode, byte nextHeader, uint epochTime,
            ReadOnlySpan<byte> secretHash, ReadOnlySpan<byte> payload)
        {
            int idLen = IdLenFor(identity.Length);
            int hashSize = HashSize(hashMethod);
            if (hashSize == 0)
                throw new ArgumentException("AYIYA requires a hash method (MD5 or SHA-1) for a signed packet.", nameof(hashMethod));
            if (secretHash.Length != hashSize)
                throw new ArgumentException($"secretHash must be {hashSize} bytes for {hashMethod}.", nameof(secretHash));
            int sigLenWords = hashSize / 4; // digest sizes (16/20) are multiples of 4

            int identityLength = identity.Length;
            int signatureOffset = HeaderPrefixLength + identityLength;
            int payloadOffset = signatureOffset + hashSize;

            byte[] buffer = new byte[payloadOffset + payload.Length];
            buffer[0] = (byte)((idLen << 4) | ((byte)idType & 0x0F));
            buffer[1] = (byte)((sigLenWords << 4) | ((byte)hashMethod & 0x0F));
            buffer[2] = (byte)(((byte)authMethod << 4) | ((byte)opcode & 0x0F));
            buffer[3] = nextHeader;
            WriteUInt32BigEndian(buffer.AsSpan(FixedHeaderLength), epochTime);
            identity.CopyTo(buffer.AsSpan(HeaderPrefixLength));
            secretHash.CopyTo(buffer.AsSpan(signatureOffset, hashSize)); // signature field = H(secret) before signing
            payload.CopyTo(buffer.AsSpan(payloadOffset));

            Span<byte> digest = stackalloc byte[hashSize];
            ComputeDigest(hashMethod, buffer, digest);
            digest.CopyTo(buffer.AsSpan(signatureOffset, hashSize)); // overwrite field with the signature
            return buffer;
        }

        /// <summary>
        /// Parses the structural header of an AYIYA datagram (no crypto). Returns <c>false</c> for a runt (shorter than the
        /// 8-byte prefix) or a datagram whose declared identity + signature run past the buffer. On success
        /// <paramref name="header"/> holds every field and the identity/signature/payload offsets. Signature verification is
        /// the separate <see cref="VerifySignature"/>.
        /// </summary>
        public static bool TryParse(ReadOnlySpan<byte> datagram, out AyiyaHeader header)
        {
            header = default;
            if (datagram.Length < HeaderPrefixLength) return false;

            byte b0 = datagram[0], b1 = datagram[1], b2 = datagram[2];
            int idLen = (b0 >> 4) & 0x0F;
            var idType = (AyiyaIdType)(b0 & 0x0F);
            int sigLenWords = (b1 >> 4) & 0x0F;
            var hashMethod = (AyiyaHashMethod)(b1 & 0x0F);
            var authMethod = (AyiyaAuthMethod)((b2 >> 4) & 0x0F);
            var opcode = (AyiyaOpcode)(b2 & 0x0F);
            byte nextHeader = datagram[3];
            uint epochTime = ReadUInt32BigEndian(datagram.Slice(FixedHeaderLength));

            int identityLength = 1 << idLen;
            int signatureLength = sigLenWords * 4;
            int identityOffset = HeaderPrefixLength;
            int signatureOffset = identityOffset + identityLength;
            int payloadOffset = signatureOffset + signatureLength;
            if (datagram.Length < payloadOffset) return false; // identity/signature truncated

            header = new AyiyaHeader((byte)idLen, idType, (byte)sigLenWords, hashMethod, authMethod, opcode, nextHeader,
                epochTime, identityOffset, identityLength, signatureOffset, signatureLength,
                payloadOffset, datagram.Length - payloadOffset);
            return true;
        }

        /// <summary>
        /// Verifies the shared-secret signature of a datagram already parsed into <paramref name="header"/> against
        /// <paramref name="secretHash"/> = <c>H(password)</c>. Recomputes the aiccu algorithm (replace signature field with
        /// <paramref name="secretHash"/>, hash the whole datagram, constant-time-compare with the received signature).
        /// Returns <c>false</c> on any mismatch, an unsupported/absent hash, a signature length that disagrees with the hash
        /// size, or a wrong-length <paramref name="secretHash"/>.
        /// </summary>
        public static bool VerifySignature(ReadOnlySpan<byte> datagram, in AyiyaHeader header, ReadOnlySpan<byte> secretHash)
        {
            int hashSize = HashSize(header.HashMethod);
            if (hashSize == 0) return false;
            if (header.SignatureLength != hashSize) return false;
            if (secretHash.Length != hashSize) return false;
            if (datagram.Length < header.PayloadOffset) return false;

            Span<byte> received = stackalloc byte[hashSize];
            datagram.Slice(header.SignatureOffset, hashSize).CopyTo(received);

            byte[] scratch = datagram.ToArray();
            secretHash.CopyTo(scratch.AsSpan(header.SignatureOffset, hashSize));
            Span<byte> digest = stackalloc byte[hashSize];
            ComputeDigest(header.HashMethod, scratch, digest);

            return FixedTimeEquals(digest, received);
        }

        static void ComputeDigest(AyiyaHashMethod method, ReadOnlySpan<byte> data, Span<byte> destination)
        {
            switch (method)
            {
                case AyiyaHashMethod.Sha1:
#if NET5_0_OR_GREATER
                    SHA1.HashData(data, destination);
#else
                    using (var sha = SHA1.Create())
                        sha.ComputeHash(data.ToArray()).AsSpan(0, 20).CopyTo(destination);
#endif
                    break;
                case AyiyaHashMethod.Md5:
#if NET5_0_OR_GREATER
                    MD5.HashData(data, destination);
#else
                    using (var md5 = MD5.Create())
                        md5.ComputeHash(data.ToArray()).AsSpan(0, 16).CopyTo(destination);
#endif
                    break;
                default:
                    throw new NotSupportedException($"AYIYA hash method {method} is not supported (expected MD5 or SHA-1).");
            }
        }

        static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
#if NETSTANDARD2_0
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
#else
            return CryptographicOperations.FixedTimeEquals(a, b);
#endif
        }

        static void WriteUInt32BigEndian(Span<byte> destination, uint value)
        {
            destination[0] = (byte)(value >> 24);
            destination[1] = (byte)(value >> 16);
            destination[2] = (byte)(value >> 8);
            destination[3] = (byte)value;
        }

        static uint ReadUInt32BigEndian(ReadOnlySpan<byte> source)
            => ((uint)source[0] << 24) | ((uint)source[1] << 16) | ((uint)source[2] << 8) | source[3];
    }
}
