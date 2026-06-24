using TqkLibrary.VpnClient.Ssh.Wire;
using TqkLibrary.VpnClient.Ssh.Wire.Enums;

namespace TqkLibrary.VpnClient.Ssh.Transport
{
    /// <summary>
    /// The SSH_MSG_KEXINIT message (RFC 4253 §7.1): a 16-byte random cookie, ten algorithm name-lists (kex; host-key;
    /// cipher c→s / s→c; MAC c→s / s→c; compression c→s / s→c; languages c→s / s→c), a
    /// <c>first_kex_packet_follows</c> flag and a reserved uint32. The exact payload bytes (type byte included) are what
    /// the exchange hash hashes as I_C / I_S, so the codec round-trips them losslessly and <see cref="Encode"/> returns
    /// that buffer for the caller to keep.
    /// </summary>
    public sealed class SshKexInit
    {
        /// <summary>The 16-byte random cookie.</summary>
        public byte[] Cookie { get; set; } = new byte[16];

        /// <summary>Key-exchange algorithm name-list (preference order).</summary>
        public string[] KexAlgorithms { get; set; } = Array.Empty<string>();

        /// <summary>Server host-key algorithm name-list.</summary>
        public string[] ServerHostKeyAlgorithms { get; set; } = Array.Empty<string>();

        /// <summary>Cipher name-list, client→server.</summary>
        public string[] EncryptionAlgorithmsClientToServer { get; set; } = Array.Empty<string>();

        /// <summary>Cipher name-list, server→client.</summary>
        public string[] EncryptionAlgorithmsServerToClient { get; set; } = Array.Empty<string>();

        /// <summary>MAC name-list, client→server.</summary>
        public string[] MacAlgorithmsClientToServer { get; set; } = Array.Empty<string>();

        /// <summary>MAC name-list, server→client.</summary>
        public string[] MacAlgorithmsServerToClient { get; set; } = Array.Empty<string>();

        /// <summary>Compression name-list, client→server.</summary>
        public string[] CompressionAlgorithmsClientToServer { get; set; } = Array.Empty<string>();

        /// <summary>Compression name-list, server→client.</summary>
        public string[] CompressionAlgorithmsServerToClient { get; set; } = Array.Empty<string>();

        /// <summary>Languages name-list, client→server (usually empty).</summary>
        public string[] LanguagesClientToServer { get; set; } = Array.Empty<string>();

        /// <summary>Languages name-list, server→client (usually empty).</summary>
        public string[] LanguagesServerToClient { get; set; } = Array.Empty<string>();

        /// <summary>The first_kex_packet_follows flag (this client never guesses, so it sends false).</summary>
        public bool FirstKexPacketFollows { get; set; }

        /// <summary>Builds a client KEXINIT advertising exactly what this minimal client supports, with a fresh random cookie.</summary>
        public static SshKexInit CreateClientDefault()
        {
            byte[] cookie = SshRandom.Bytes(16);
            return new SshKexInit
            {
                Cookie = cookie,
                KexAlgorithms = new[] { "curve25519-sha256", "curve25519-sha256@libssh.org" },
                ServerHostKeyAlgorithms = new[] { "ssh-ed25519" },
                EncryptionAlgorithmsClientToServer = new[] { "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com" },
                EncryptionAlgorithmsServerToClient = new[] { "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com" },
                MacAlgorithmsClientToServer = new[] { "hmac-sha2-256" },   // ignored when an AEAD cipher is selected
                MacAlgorithmsServerToClient = new[] { "hmac-sha2-256" },
                CompressionAlgorithmsClientToServer = new[] { "none" },
                CompressionAlgorithmsServerToClient = new[] { "none" },
                LanguagesClientToServer = Array.Empty<string>(),
                LanguagesServerToClient = Array.Empty<string>(),
                FirstKexPacketFollows = false,
            };
        }

        /// <summary>Serialises the message to its exact payload bytes (type byte 20 first); keep this for the exchange hash (I_C/I_S).</summary>
        public byte[] Encode()
        {
            var w = new SshWriter();
            w.WriteByte((byte)SshMessageNumber.KexInit);
            w.WriteRaw(Cookie);
            w.WriteNameList(KexAlgorithms);
            w.WriteNameList(ServerHostKeyAlgorithms);
            w.WriteNameList(EncryptionAlgorithmsClientToServer);
            w.WriteNameList(EncryptionAlgorithmsServerToClient);
            w.WriteNameList(MacAlgorithmsClientToServer);
            w.WriteNameList(MacAlgorithmsServerToClient);
            w.WriteNameList(CompressionAlgorithmsClientToServer);
            w.WriteNameList(CompressionAlgorithmsServerToClient);
            w.WriteNameList(LanguagesClientToServer);
            w.WriteNameList(LanguagesServerToClient);
            w.WriteBoolean(FirstKexPacketFollows);
            w.WriteUInt32(0); // reserved
            return w.ToArray();
        }

        /// <summary>Parses a KEXINIT payload (type byte 20 first). Throws <see cref="SshProtocolException"/> on the wrong type.</summary>
        public static SshKexInit Decode(ReadOnlySpan<byte> payload)
        {
            var r = new SshReader(payload);
            byte type = r.ReadByte();
            if (type != (byte)SshMessageNumber.KexInit)
                throw new SshProtocolException($"Expected SSH_MSG_KEXINIT (20) but got message {type}.");
            return new SshKexInit
            {
                Cookie = r.ReadRaw(16).ToArray(),
                KexAlgorithms = r.ReadNameList(),
                ServerHostKeyAlgorithms = r.ReadNameList(),
                EncryptionAlgorithmsClientToServer = r.ReadNameList(),
                EncryptionAlgorithmsServerToClient = r.ReadNameList(),
                MacAlgorithmsClientToServer = r.ReadNameList(),
                MacAlgorithmsServerToClient = r.ReadNameList(),
                CompressionAlgorithmsClientToServer = r.ReadNameList(),
                CompressionAlgorithmsServerToClient = r.ReadNameList(),
                LanguagesClientToServer = r.ReadNameList(),
                LanguagesServerToClient = r.ReadNameList(),
                FirstKexPacketFollows = r.ReadBoolean(),
            };
        }

        /// <summary>
        /// Negotiates one algorithm by RFC 4253 §7.1 client-preference rule: the first client algorithm the server also
        /// supports. Returns null if no algorithm is common.
        /// </summary>
        public static string? Negotiate(string[] clientPreference, string[] serverSupported)
        {
            foreach (string c in clientPreference)
                foreach (string s in serverSupported)
                    if (c == s) return c;
            return null;
        }
    }
}
