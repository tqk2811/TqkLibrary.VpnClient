using System.Buffers.Binary;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Enums;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;
// Alias the BouncyCastle types directly (its Crypto namespace clashes with this solution's interfaces — same pattern
// as Crypto/Salsa20.cs). The codec drives Salsa20Engine itself (rather than the Salsa20 wrapper) because it needs the
// key-stream to continue across two reads: block 0 supplies the one-time Poly1305 key, the rest encrypts the payload.
using Salsa20Engine = Org.BouncyCastle.Crypto.Engines.Salsa20Engine;
using Poly1305 = Org.BouncyCastle.Crypto.Macs.Poly1305;
using KeyParameter = Org.BouncyCastle.Crypto.Parameters.KeyParameter;
using ParametersWithIV = Org.BouncyCastle.Crypto.Parameters.ParametersWithIV;

namespace TqkLibrary.VpnClient.ZeroTier.Vl1
{
    /// <summary>
    /// Seals and opens VL1 packets, matching ZeroTier's <c>Packet::armor</c>/<c>dearmor</c> for the two Curve25519
    /// cipher suites:
    /// <list type="bullet">
    ///   <item><description><see cref="Vl1CipherSuite.Poly1305None"/> (0) — payload is NOT encrypted, only
    ///   Poly1305-authenticated. HELLO uses this, since the receiver must read the sender's identity before any session
    ///   key exists.</description></item>
    ///   <item><description><see cref="Vl1CipherSuite.Salsa2012Poly1305"/> (1) — payload encrypted with Salsa20/12 and
    ///   Poly1305-authenticated (the normal data cipher suite).</description></item>
    /// </list>
    /// Both derive the per-packet keystream from a <b>mangled</b> key (see <see cref="MangleKey"/>): the shared key is
    /// XORed with the packet ID, the source/destination addresses, the flags byte (hops masked off) and the packet size,
    /// so the key space is bound to the packet header and split per direction. The Salsa20/12 IV is the 8-byte packet ID;
    /// keystream block 0 (first 32 bytes) is the one-time Poly1305 key and — for cipher 1 — the keystream continues to
    /// encrypt the verb byte and payload. Poly1305 covers the encrypted section (verb byte onward); its 16-byte tag is
    /// truncated to the first 8 bytes and stored in the MAC field (header bytes [19..27)).
    /// </summary>
    public sealed class Vl1PacketCodec
    {
        const int Poly1305KeyBytes = 32;
        // ZeroTier derives the one-time Poly1305 key from the FIRST 64-byte Salsa20 block (using only its leading 32
        // bytes) and then encrypts the payload starting at the NEXT block — ZeroTier's Salsa20 advances block-by-block, so
        // the unused 32 bytes of block 0 are discarded, not carried into the payload keystream. BouncyCastle's
        // Salsa20Engine is byte-granular, so we must explicitly consume the full 64-byte block before encrypting.
        const int Salsa20BlockBytes = 64;

        /// <summary>
        /// Builds a sealed VL1 packet from <paramref name="header"/> (its <c>Cipher</c> selects the suite — default
        /// <see cref="Vl1CipherSuite.Salsa2012Poly1305"/> if left unset), the <paramref name="key"/> (≥ 32 bytes shared
        /// key) and the plaintext <paramref name="payload"/> (the bytes that follow the verb). The verb itself comes from
        /// <c>header.Verb</c>.
        /// </summary>
        public byte[] Seal(Vl1Header header, ReadOnlySpan<byte> key, ReadOnlySpan<byte> payload)
        {
            if (header is null) throw new ArgumentNullException(nameof(header));
            if (key.Length < 32) throw new ArgumentException("key must be >= 32 bytes", nameof(key));

            // The caller selects the suite via header.Cipher. Poly1305None (0) keeps the payload in the clear (HELLO);
            // any other value is treated as the encrypting Salsa2012Poly1305 suite.
            bool encrypt = header.Cipher != Vl1CipherSuite.Poly1305None;
            header.Cipher = encrypt ? Vl1CipherSuite.Salsa2012Poly1305 : Vl1CipherSuite.Poly1305None;

            int plainLen = 1 + payload.Length; // verb byte + payload
            // The verb byte sits at EncryptedSectionOffset (27), so the packet is the 27-byte clear header followed by
            // the plainLen-byte encrypted section — NOT Size(28)+plainLen (that double-counts the verb byte).
            byte[] packet = new byte[Vl1Header.EncryptedSectionOffset + plainLen];

            WriteHeaderClear(header, packet);

            // Encrypted/authenticated section: verb byte then payload.
            Span<byte> enc = packet.AsSpan(Vl1Header.EncryptedSectionOffset, plainLen);
            enc[0] = (byte)(((header.VerbFlags & 0x07) << 5) | ((int)header.Verb & 0x1F));
            payload.CopyTo(enc.Slice(1));

            // Mangle the key against this packet's header + size, then key Salsa20/12 with it (IV = packet ID).
            byte[] mangled = MangleKey(key, packet);
            byte[] nonce = NonceFromPacketId(header.PacketId);
            var engine = NewEngine(mangled, nonce);

            // Block 0 -> Poly1305 one-time key (first 32 bytes; the rest of the 64-byte block is discarded so the payload
            // cipher starts at block 1, matching ZeroTier's block-granular Salsa20).
            byte[] polyKey = NextKeystream(engine, Poly1305KeyBytes);
            DiscardToNextBlock(engine, Poly1305KeyBytes);

            if (encrypt)
            {
                byte[] cipherSection = new byte[plainLen];
                engine.ProcessBytes(enc.ToArray(), 0, plainLen, cipherSection, 0);
                cipherSection.CopyTo(enc);
            }

            // Poly1305 over the (possibly still-plaintext) encrypted section; truncate tag to 8 bytes.
            byte[] tag = ComputeMac(polyKey, enc);
            tag.AsSpan(0, Vl1Header.MacSize).CopyTo(packet.AsSpan(Vl1Header.MacOffset, Vl1Header.MacSize));

            return packet;
        }

        /// <summary>
        /// Verifies and decrypts a sealed VL1 packet. On success returns true and yields the parsed header (with verb)
        /// and the payload (the bytes after the verb — already decrypted for cipher 1, verbatim for cipher 0). Returns
        /// false without writing payload on a malformed packet, an unsupported cipher suite or a MAC mismatch.
        /// </summary>
        public bool Open(ReadOnlySpan<byte> packet, ReadOnlySpan<byte> key, out Vl1Header header, out byte[] payload)
        {
            header = new Vl1Header();
            payload = Array.Empty<byte>();
            // Smallest valid packet = 27-byte clear header + at least the 1-byte verb.
            if (packet.Length < Vl1Header.EncryptedSectionOffset + 1) return false;
            if (key.Length < 32) return false;

            ReadHeaderClear(packet, header);
            bool encrypt;
            switch (header.Cipher)
            {
                case Vl1CipherSuite.Poly1305None: encrypt = false; break;
                case Vl1CipherSuite.Salsa2012Poly1305: encrypt = true; break;
                default: return false;
            }

            int cipherLen = packet.Length - Vl1Header.EncryptedSectionOffset; // verb + payload
            ReadOnlySpan<byte> section = packet.Slice(Vl1Header.EncryptedSectionOffset, cipherLen);

            byte[] mangled = MangleKey(key, packet);
            byte[] nonce = NonceFromPacketId(header.PacketId);
            var engine = NewEngine(mangled, nonce);

            byte[] polyKey = NextKeystream(engine, Poly1305KeyBytes);
            DiscardToNextBlock(engine, Poly1305KeyBytes);

            // Constant-time-ish MAC check (over the on-wire section) before touching the plaintext.
            byte[] expected = ComputeMac(polyKey, section);
            ReadOnlySpan<byte> got = packet.Slice(Vl1Header.MacOffset, Vl1Header.MacSize);
            if (!CryptoBytes.FixedTimeEquals(expected.AsSpan(0, Vl1Header.MacSize), got)) return false;

            byte[] plain;
            if (encrypt)
            {
                plain = new byte[cipherLen];
                engine.ProcessBytes(section.ToArray(), 0, cipherLen, plain, 0);
            }
            else
            {
                plain = section.ToArray();
            }

            header.VerbFlags = (byte)((plain[0] >> 5) & 0x07);
            header.Verb = (Vl1Verb)(plain[0] & 0x1F);
            payload = plain.AsSpan(1).ToArray();
            return true;
        }

        // ---- key mangling -----------------------------------------------------------------------------------

        /// <summary>
        /// Derives the per-packet Salsa20 key from the shared <paramref name="key"/> by XORing its leading bytes with
        /// the packet header (ZeroTier <c>_salsa20MangleKey</c>): bytes [0..18) with the IV + dest + source, byte 18 with
        /// the flags (hop count masked off, since relays change it), bytes 19/20 with the little-endian packet size, and
        /// the rest unchanged. Binding the key to the header makes every packet a fresh key space and splits A→B from B→A.
        /// </summary>
        public static byte[] MangleKey(ReadOnlySpan<byte> key, ReadOnlySpan<byte> packet)
        {
            byte[] m = new byte[32];
            // [0..18) = IV(8) + dest(5) + source(5)
            for (int i = 0; i < 18; i++) m[i] = (byte)(key[i] ^ packet[i]);
            // [18] = flags, with the low 3 hop-count bits masked off
            m[18] = (byte)(key[18] ^ (packet[Vl1Header.FlagsOffset] & 0xf8));
            // [19],[20] = packet size, little-endian
            int size = packet.Length;
            m[19] = (byte)(key[19] ^ (byte)(size & 0xff));
            m[20] = (byte)(key[20] ^ (byte)((size >> 8) & 0xff));
            // rest unchanged
            for (int i = 21; i < 32; i++) m[i] = key[i];
            return m;
        }

        // ---- header (clear portion) -------------------------------------------------------------------------

        static void WriteHeaderClear(Vl1Header header, Span<byte> packet)
        {
            BinaryPrimitives.WriteUInt64BigEndian(packet.Slice(0, 8), header.PacketId);
            header.Destination.Write(packet.Slice(8, ZeroTierAddress.SizeInBytes));
            header.Source.Write(packet.Slice(13, ZeroTierAddress.SizeInBytes));
            // FFCCCHHH: flags (bits 6-7) | cipher (bits 3-5) | hops (bits 0-2)
            packet[Vl1Header.FlagsOffset] = (byte)(((header.Flags & 0x03) << 6) | (((int)header.Cipher & 0x07) << 3) | (header.Hops & 0x07));
            // MAC field [19..27) is filled by the caller after the tag is computed.
        }

        static void ReadHeaderClear(ReadOnlySpan<byte> packet, Vl1Header header)
        {
            header.PacketId = BinaryPrimitives.ReadUInt64BigEndian(packet.Slice(0, 8));
            header.Destination = ZeroTierAddress.Read(packet.Slice(8, ZeroTierAddress.SizeInBytes));
            header.Source = ZeroTierAddress.Read(packet.Slice(13, ZeroTierAddress.SizeInBytes));
            byte b = packet[Vl1Header.FlagsOffset];
            header.Flags = (byte)((b >> 6) & 0x03);
            header.Cipher = (Vl1CipherSuite)((b >> 3) & 0x07);
            header.Hops = (byte)(b & 0x07);
        }

        // ---- crypto helpers ---------------------------------------------------------------------------------

        static byte[] NonceFromPacketId(ulong packetId)
        {
            byte[] nonce = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(nonce, packetId);
            return nonce;
        }

        static Salsa20Engine NewEngine(ReadOnlySpan<byte> key, byte[] nonce)
        {
            var engine = new Salsa20Engine(12); // Salsa20/12
            engine.Init(true, new ParametersWithIV(new KeyParameter(key.Slice(0, 32).ToArray()), nonce));
            return engine;
        }

        static byte[] NextKeystream(Salsa20Engine engine, int count)
        {
            byte[] zeros = new byte[count];
            byte[] ks = new byte[count];
            engine.ProcessBytes(zeros, 0, count, ks, 0);
            return ks;
        }

        // Advance the (byte-granular BouncyCastle) engine past the remainder of the current 64-byte Salsa20 block, so the
        // next ProcessBytes starts on a block boundary — matching ZeroTier's block-granular Salsa20, which discards the
        // unused tail of the block it took the Poly1305 key from. <paramref name="alreadyConsumed"/> is how many bytes of
        // the current block were already produced.
        static void DiscardToNextBlock(Salsa20Engine engine, int alreadyConsumed)
        {
            int remainder = alreadyConsumed % Salsa20BlockBytes;
            if (remainder == 0) return;
            int skip = Salsa20BlockBytes - remainder;
            byte[] zeros = new byte[skip];
            byte[] sink = new byte[skip];
            engine.ProcessBytes(zeros, 0, skip, sink, 0);
        }

        static byte[] ComputeMac(byte[] polyKey, ReadOnlySpan<byte> data)
        {
            var mac = new Poly1305();
            mac.Init(new KeyParameter(polyKey));
            byte[] buf = data.ToArray();
            mac.BlockUpdate(buf, 0, buf.Length);
            byte[] tag = new byte[16];
            mac.DoFinal(tag, 0);
            return tag;
        }
    }
}
