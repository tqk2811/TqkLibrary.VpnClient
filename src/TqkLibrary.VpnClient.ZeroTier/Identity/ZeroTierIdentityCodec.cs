using TqkLibrary.VpnClient.ZeroTier.Identity.Models;

namespace TqkLibrary.VpnClient.ZeroTier.Identity
{
    /// <summary>
    /// Parses and serialises ZeroTier V1 identities in both the human-readable string form used by
    /// <c>zerotier-idtool</c> and the binary on-wire form.
    /// <para>
    /// <b>String form:</b> <c>&lt;address&gt;:0:&lt;publicKeyHex&gt;[:&lt;privateKeyHex&gt;]</c> — the address is 10 hex
    /// digits, <c>0</c> is the identity type (C25519/x25519), the public key is 128 hex chars (64 bytes) and the
    /// optional private key is another 128 hex chars.
    /// </para>
    /// <para>
    /// <b>Binary form:</b> <c>address(5) || type(1=0x00) || publicKey(64) || [privateKeyLen(1) || privateKey(64)]</c>.
    /// A <c>privateKeyLen</c> of 0 (or a truncated buffer) denotes a public-only identity.
    /// </para>
    /// The codec does <b>not</b> recompute or verify the address against the public key — pair it with
    /// <see cref="ZeroTierAddressDerivation"/> for that.
    /// </summary>
    public sealed class ZeroTierIdentityCodec
    {
        const byte IdentityTypeC25519 = 0x00;

        // ---- string form -------------------------------------------------------------------------------------

        /// <summary>Parses an idtool-style identity string. Throws <see cref="FormatException"/> on malformed input.</summary>
        public ZeroTierIdentity ParseString(string text)
        {
            if (text is null) throw new ArgumentNullException(nameof(text));
            string[] parts = text.Trim().Split(':');
            if (parts.Length < 3) throw new FormatException("identity must have at least address:type:publicKey");

            if (parts[1] != "0") throw new FormatException($"unsupported identity type '{parts[1]}' (only 0 / C25519 supported)");

            var identity = new ZeroTierIdentity
            {
                Address = ZeroTierAddress.Parse(parts[0]),
                PublicKey = FromHex(parts[2], ZeroTierIdentity.PublicKeySize, "public key"),
            };
            if (parts.Length >= 4 && parts[3].Length > 0)
                identity.PrivateKey = FromHex(parts[3], ZeroTierIdentity.PrivateKeySize, "private key");
            return identity;
        }

        /// <summary>Serialises an identity to the idtool string form (public-only unless <paramref name="includePrivate"/>).</summary>
        public string ToString(ZeroTierIdentity identity, bool includePrivate)
        {
            if (identity is null) throw new ArgumentNullException(nameof(identity));
            if (identity.PublicKey.Length != ZeroTierIdentity.PublicKeySize)
                throw new ArgumentException("public key must be 64 bytes", nameof(identity));

            string s = $"{identity.Address}:0:{ToHex(identity.PublicKey)}";
            if (includePrivate)
            {
                if (!identity.HasPrivate) throw new InvalidOperationException("identity has no private key");
                s += $":{ToHex(identity.PrivateKey!)}";
            }
            return s;
        }

        // ---- binary form -------------------------------------------------------------------------------------

        /// <summary>Encodes an identity to its binary form (includes the private key iff <paramref name="includePrivate"/>).</summary>
        public byte[] EncodeBinary(ZeroTierIdentity identity, bool includePrivate)
        {
            if (identity is null) throw new ArgumentNullException(nameof(identity));
            if (identity.PublicKey.Length != ZeroTierIdentity.PublicKeySize)
                throw new ArgumentException("public key must be 64 bytes", nameof(identity));

            bool priv = includePrivate && identity.HasPrivate;
            int len = ZeroTierAddress.SizeInBytes + 1 + ZeroTierIdentity.PublicKeySize + (priv ? 1 + ZeroTierIdentity.PrivateKeySize : 1);
            byte[] buffer = new byte[len];

            int o = 0;
            identity.Address.Write(buffer.AsSpan(o, ZeroTierAddress.SizeInBytes));
            o += ZeroTierAddress.SizeInBytes;
            buffer[o++] = IdentityTypeC25519;
            identity.PublicKey.CopyTo(buffer.AsSpan(o));
            o += ZeroTierIdentity.PublicKeySize;
            if (priv)
            {
                buffer[o++] = ZeroTierIdentity.PrivateKeySize;
                identity.PrivateKey!.CopyTo(buffer.AsSpan(o));
            }
            else
            {
                buffer[o++] = 0; // private-key length 0
            }
            return buffer;
        }

        /// <summary>Parses the binary identity form. Returns false on a malformed or unsupported buffer.</summary>
        public bool TryDecodeBinary(ReadOnlySpan<byte> data, out ZeroTierIdentity identity)
        {
            identity = new ZeroTierIdentity();
            int min = ZeroTierAddress.SizeInBytes + 1 + ZeroTierIdentity.PublicKeySize;
            if (data.Length < min) return false;

            int o = 0;
            var address = ZeroTierAddress.Read(data.Slice(o, ZeroTierAddress.SizeInBytes));
            o += ZeroTierAddress.SizeInBytes;
            if (data[o++] != IdentityTypeC25519) return false;

            byte[] pub = data.Slice(o, ZeroTierIdentity.PublicKeySize).ToArray();
            o += ZeroTierIdentity.PublicKeySize;

            identity.Address = address;
            identity.PublicKey = pub;

            // Optional private-key length byte + body.
            if (o < data.Length)
            {
                int privLen = data[o++];
                if (privLen == ZeroTierIdentity.PrivateKeySize && data.Length - o >= privLen)
                    identity.PrivateKey = data.Slice(o, privLen).ToArray();
            }
            return true;
        }

        // ---- hex helpers -------------------------------------------------------------------------------------

        static byte[] FromHex(string hex, int expectedBytes, string what)
        {
            if (hex.Length != expectedBytes * 2)
                throw new FormatException($"{what} must be {expectedBytes * 2} hex chars, got {hex.Length}");
            byte[] result = new byte[expectedBytes];
            for (int i = 0; i < expectedBytes; i++)
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return result;
        }

        static string ToHex(byte[] data)
        {
            var sb = new System.Text.StringBuilder(data.Length * 2);
            foreach (byte b in data) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }
}
