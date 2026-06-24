using System.Globalization;

namespace TqkLibrary.VpnClient.Tailscale.Keys
{
    /// <summary>
    /// Codec for the textual Tailscale key forms used on the ts2021 wire (<c>types/key</c>): a type prefix followed by
    /// the lowercase hex of a 32-byte Curve25519 (X25519) key. Every Tailscale key — machine, node and disco — is the
    /// same 32-byte Curve25519 value, differing only by prefix:
    /// <list type="bullet">
    /// <item><c>mkey:</c> — <see cref="MachinePublicPrefix"/>, the control/machine public key.</item>
    /// <item><c>nodekey:</c> — <see cref="NodePublicPrefix"/>, the node (WireGuard) public key.</item>
    /// <item><c>discokey:</c> — <see cref="DiscoPublicPrefix"/>, the disco (NAT-traversal) public key.</item>
    /// <item><c>privkey:</c> — <see cref="PrivatePrefix"/>, shared by machine and node private keys.</item>
    /// </list>
    /// The <c>nodekey:</c> form is exactly the WireGuard peer public key (no transformation), so the netmap maps
    /// straight onto a <see cref="WireGuard.Config.WireGuardPeer"/>.
    /// </summary>
    public static class TailscaleKey
    {
        /// <summary>The textual prefix of a machine public key (<c>key.MachinePublic</c>).</summary>
        public const string MachinePublicPrefix = "mkey:";

        /// <summary>The textual prefix of a node public key (<c>key.NodePublic</c>) — the WireGuard peer public key.</summary>
        public const string NodePublicPrefix = "nodekey:";

        /// <summary>The textual prefix of a disco public key (<c>key.DiscoPublic</c>).</summary>
        public const string DiscoPublicPrefix = "discokey:";

        /// <summary>The textual prefix shared by machine and node private keys (<c>key.*Private</c>).</summary>
        public const string PrivatePrefix = "privkey:";

        /// <summary>The fixed length of every Tailscale key (Curve25519).</summary>
        public const int KeyLength = 32;

        /// <summary>
        /// Formats a 32-byte key as <paramref name="prefix"/> + lowercase hex (the on-wire text form). Throws when the
        /// key is not <see cref="KeyLength"/> bytes.
        /// </summary>
        public static string Encode(string prefix, ReadOnlySpan<byte> key)
        {
            if (prefix is null) throw new ArgumentNullException(nameof(prefix));
            if (key.Length != KeyLength)
                throw new ArgumentException($"Tailscale key must be {KeyLength} bytes.", nameof(key));
            var chars = new char[prefix.Length + KeyLength * 2];
            prefix.AsSpan().CopyTo(chars);
            int pos = prefix.Length;
            for (int i = 0; i < key.Length; i++)
            {
                chars[pos++] = ToHex(key[i] >> 4);
                chars[pos++] = ToHex(key[i] & 0xF);
            }
            return new string(chars);
        }

        /// <summary>Formats a machine public key (<c>mkey:&lt;hex&gt;</c>).</summary>
        public static string EncodeMachinePublic(ReadOnlySpan<byte> key) => Encode(MachinePublicPrefix, key);

        /// <summary>Formats a node public key (<c>nodekey:&lt;hex&gt;</c>).</summary>
        public static string EncodeNodePublic(ReadOnlySpan<byte> key) => Encode(NodePublicPrefix, key);

        /// <summary>Formats a disco public key (<c>discokey:&lt;hex&gt;</c>).</summary>
        public static string EncodeDiscoPublic(ReadOnlySpan<byte> key) => Encode(DiscoPublicPrefix, key);

        /// <summary>
        /// Parses a prefixed hex key, requiring <paramref name="expectedPrefix"/>. Returns the 32 raw bytes. Throws
        /// <see cref="FormatException"/> on a wrong prefix, a non-hex body or a wrong length.
        /// </summary>
        public static byte[] Decode(string text, string expectedPrefix)
        {
            if (text is null) throw new ArgumentNullException(nameof(text));
            if (expectedPrefix is null) throw new ArgumentNullException(nameof(expectedPrefix));
            if (!text.StartsWith(expectedPrefix, StringComparison.Ordinal))
                throw new FormatException($"Tailscale key '{Truncate(text)}' does not start with the expected prefix '{expectedPrefix}'.");
            return DecodeHexBody(text, expectedPrefix.Length);
        }

        /// <summary>Parses a machine public key (<c>mkey:&lt;hex&gt;</c>) to 32 raw bytes.</summary>
        public static byte[] DecodeMachinePublic(string text) => Decode(text, MachinePublicPrefix);

        /// <summary>Parses a node public key (<c>nodekey:&lt;hex&gt;</c>) to 32 raw bytes.</summary>
        public static byte[] DecodeNodePublic(string text) => Decode(text, NodePublicPrefix);

        /// <summary>Parses a disco public key (<c>discokey:&lt;hex&gt;</c>) to 32 raw bytes.</summary>
        public static byte[] DecodeDiscoPublic(string text) => Decode(text, DiscoPublicPrefix);

        static byte[] DecodeHexBody(string text, int offset)
        {
            int hexLen = text.Length - offset;
            if (hexLen != KeyLength * 2)
                throw new FormatException($"Tailscale key body must be {KeyLength * 2} hex chars, got {hexLen}.");
            var bytes = new byte[KeyLength];
            for (int i = 0; i < KeyLength; i++)
            {
                int hi = FromHex(text[offset + i * 2]);
                int lo = FromHex(text[offset + i * 2 + 1]);
                bytes[i] = (byte)((hi << 4) | lo);
            }
            return bytes;
        }

        static char ToHex(int nibble) => (char)(nibble < 10 ? '0' + nibble : 'a' + (nibble - 10));

        static int FromHex(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw new FormatException($"Invalid hex character '{c}' in a Tailscale key.");
        }

        static string Truncate(string s) => s.Length <= 16 ? s : s.Substring(0, 16) + "...";
    }
}
