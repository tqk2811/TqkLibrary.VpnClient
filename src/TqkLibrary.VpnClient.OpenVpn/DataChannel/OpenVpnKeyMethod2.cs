using System.Buffers.Binary;
using System.Text;
using TqkLibrary.VpnClient.Crypto;

namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// OpenVPN key-method-2: the client and server each send a random <see cref="OpenVpnKeySource2"/> over the
    /// established TLS control channel, then both derive the data-channel keys from the combined material with the
    /// TLS 1.0 PRF (<see cref="Tls1Prf"/>). Message on the TLS stream:
    /// <code>
    ///   uint32 0 | key_method=2 | key_source2 | P_string(options) | [P_string(user) P_string(pass) P_string(peer_info)]
    /// </code>
    /// (the client adds the 48-byte pre-master to its key_source2 and the user/pass/peer-info strings; the server
    /// sends only its two randoms + options). A <c>P_string</c> is a 16-bit big-endian length (counting the trailing
    /// NUL) followed by the bytes and the NUL. This is the client side — building the client message and reading the
    /// server's; the server role lives only in tests.
    /// </summary>
    public static class OpenVpnKeyMethod2
    {
        const byte KeyMethod = 2;
        const int SessionIdSize = 8;
        const int Key2Size = 256;
        const int MasterSecretSize = 48;
        static readonly byte[] MasterLabel = Encoding.ASCII.GetBytes("OpenVPN master secret");
        static readonly byte[] ExpansionLabel = Encoding.ASCII.GetBytes("OpenVPN key expansion");

        /// <summary>
        /// Builds the client's key-method-2 message. <paramref name="optionsString"/> is the OCC options string the
        /// server compares for compatibility; <paramref name="username"/>/<paramref name="password"/> carry
        /// auth-user-pass (empty strings when none); <paramref name="peerInfo"/> is the optional IV_* peer-info block.
        /// </summary>
        public static byte[] BuildClientMessage(OpenVpnKeySource2 client, string optionsString,
            string? username = null, string? password = null, string? peerInfo = null)
        {
            if (client is null) throw new ArgumentNullException(nameof(client));
            if (client.PreMaster.Length != OpenVpnKeySource2.PreMasterSize)
                throw new ArgumentException("client key source must carry a pre-master.", nameof(client));

            var buf = new List<byte>(256);
            buf.AddRange(new byte[4]);          // uint32 0
            buf.Add(KeyMethod);                 // key_method = 2
            buf.AddRange(client.PreMaster);     // key_source2: pre-master (client only)
            buf.AddRange(client.Random1);
            buf.AddRange(client.Random2);
            WriteString(buf, optionsString);
            WriteString(buf, username ?? string.Empty);
            WriteString(buf, password ?? string.Empty);
            if (peerInfo != null) WriteString(buf, peerInfo);
            return buf.ToArray();
        }

        /// <summary>
        /// Parses the server's key-method-2 reply: <c>uint32 0 | key_method=2 | random1 | random2 | P_string(options)</c>.
        /// Returns false if the framing is malformed or the key method is not 2.
        /// </summary>
        public static bool TryParseServerMessage(ReadOnlySpan<byte> message, out OpenVpnKeySource2 serverKeySource, out string options)
        {
            serverKeySource = null!;
            options = string.Empty;

            int need = 4 + 1 + OpenVpnKeySource2.RandomSize * 2 + 2;
            if (message.Length < need) return false;
            // uint32 0 sentinel + key_method == 2
            if (BinaryPrimitives.ReadUInt32BigEndian(message.Slice(0, 4)) != 0) return false;
            if (message[4] != KeyMethod) return false;

            int pos = 5;
            byte[] r1 = message.Slice(pos, OpenVpnKeySource2.RandomSize).ToArray(); pos += OpenVpnKeySource2.RandomSize;
            byte[] r2 = message.Slice(pos, OpenVpnKeySource2.RandomSize).ToArray(); pos += OpenVpnKeySource2.RandomSize;
            if (!TryReadString(message, ref pos, out options)) return false;

            serverKeySource = new OpenVpnKeySource2(Array.Empty<byte>(), r1, r2);
            return true;
        }

        /// <summary>
        /// Derives the data-channel keys from the two key sources and the session ids. The TLS 1.0 PRF produces the
        /// 48-byte master secret then the 256-byte key2 (two {cipher, hmac} sets, same layout as a static key). For
        /// AES-256-GCM each direction takes a 32-byte cipher key + an 8-byte implicit IV (from the hmac half).
        /// <paramref name="isServer"/> selects the role's set: client out = set 1 / in = set 0, server the reverse.
        /// </summary>
        public static OpenVpnDataChannelKeys DeriveDataKeys(OpenVpnKeySource2 client, OpenVpnKeySource2 server,
            ulong clientSessionId, ulong serverSessionId, bool isServer)
        {
            if (client.PreMaster.Length != OpenVpnKeySource2.PreMasterSize)
                throw new ArgumentException("client key source must carry a pre-master.", nameof(client));

            byte[] masterSeed = Concat(client.Random1, server.Random1);
            byte[] master = Tls1Prf.Compute(client.PreMaster, MasterLabel, masterSeed, MasterSecretSize);

            byte[] expansionSeed = new byte[OpenVpnKeySource2.RandomSize * 2 + SessionIdSize * 2];
            int p = 0;
            Array.Copy(client.Random2, 0, expansionSeed, p, OpenVpnKeySource2.RandomSize); p += OpenVpnKeySource2.RandomSize;
            Array.Copy(server.Random2, 0, expansionSeed, p, OpenVpnKeySource2.RandomSize); p += OpenVpnKeySource2.RandomSize;
            BinaryPrimitives.WriteUInt64BigEndian(expansionSeed.AsSpan(p, SessionIdSize), clientSessionId); p += SessionIdSize;
            BinaryPrimitives.WriteUInt64BigEndian(expansionSeed.AsSpan(p, SessionIdSize), serverSessionId);

            byte[] key2 = Tls1Prf.Compute(master, ExpansionLabel, expansionSeed, Key2Size);

            // Reuse the static-key model: key2 has the same {cipher[64]|hmac[64]} × 2 layout.
            var sets = OpenVpnStaticKey.FromBytes(key2);
            (int outSet, int inSet) = isServer ? (0, 1) : (1, 0);
            return new OpenVpnDataChannelKeys(
                sendCipherKey: sets.CipherKey(outSet, OpenVpnDataChannelKeys.CipherKeySize),
                sendImplicitIv: sets.HmacKey(outSet, OpenVpnDataChannelKeys.ImplicitIvSize),
                receiveCipherKey: sets.CipherKey(inSet, OpenVpnDataChannelKeys.CipherKeySize),
                receiveImplicitIv: sets.HmacKey(inSet, OpenVpnDataChannelKeys.ImplicitIvSize));
        }

        static void WriteString(List<byte> buf, string s)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(s);
            int len = bytes.Length + 1; // include the trailing NUL
            buf.Add((byte)(len >> 8));
            buf.Add((byte)len);
            buf.AddRange(bytes);
            buf.Add(0);
        }

        static bool TryReadString(ReadOnlySpan<byte> buf, ref int pos, out string value)
        {
            value = string.Empty;
            if (pos + 2 > buf.Length) return false;
            int len = (buf[pos] << 8) | buf[pos + 1];
            pos += 2;
            if (len < 1 || pos + len > buf.Length) return false;
            value = Encoding.ASCII.GetString(buf.Slice(pos, len - 1).ToArray()); // strip the trailing NUL
            pos += len;
            return true;
        }

        static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] r = new byte[a.Length + b.Length];
            Array.Copy(a, 0, r, 0, a.Length);
            Array.Copy(b, 0, r, a.Length, b.Length);
            return r;
        }
    }
}
