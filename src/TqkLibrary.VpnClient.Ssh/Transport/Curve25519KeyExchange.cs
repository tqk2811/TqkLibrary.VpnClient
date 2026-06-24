using System.Security.Cryptography;
using System.Text;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Ssh.Wire;

namespace TqkLibrary.VpnClient.Ssh.Transport
{
    /// <summary>
    /// The <c>curve25519-sha256</c> key exchange (RFC 8731 / RFC 5656 §4) and the SSH key derivation (RFC 4253 §7.2).
    /// The client generates an X25519 ephemeral key, sends Q_C in SSH_MSG_KEX_ECDH_INIT and receives the server's host
    /// key K_S, ephemeral Q_S and signature in SSH_MSG_KEX_ECDH_REPLY. The shared secret X = X25519(d_C, Q_S) is
    /// reinterpreted big-endian into the integer K, encoded as an mpint, and the exchange hash is
    /// <c>H = SHA256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)</c> with every field SSH-string-encoded
    /// (length-prefixed) except K, which is an mpint. H of the first KEX is the session identifier. The negotiated
    /// encryption/IV/MAC keys are then expanded from K, H and the session id with the per-letter HASH chain.
    /// <para>This is a pure computation over the bytes the transport collected — it owns no sockets.</para>
    /// </summary>
    public sealed class Curve25519KeyExchange
    {
        readonly Curve25519DhGroup _dh = new();

        /// <summary>The client's ephemeral X25519 private key (32 bytes).</summary>
        public byte[] EphemeralPrivate { get; }

        /// <summary>The client's ephemeral X25519 public value Q_C (32 bytes) sent in KEX_ECDH_INIT.</summary>
        public byte[] EphemeralPublic { get; }

        /// <summary>Generates a fresh ephemeral key pair for one key exchange.</summary>
        public Curve25519KeyExchange()
        {
            EphemeralPrivate = _dh.GeneratePrivateKey();
            EphemeralPublic = _dh.DerivePublicValue(EphemeralPrivate);
        }

        /// <summary>The exchange hash H (also the session id for the first KEX). Valid after <see cref="ComputeSharedAndHash"/>.</summary>
        public byte[] ExchangeHash { get; private set; } = Array.Empty<byte>();

        /// <summary>The shared secret K already encoded as an SSH mpint (length-prefix + sign byte). Valid after <see cref="ComputeSharedAndHash"/>.</summary>
        public byte[] SharedSecretMpint { get; private set; } = Array.Empty<byte>();

        /// <summary>
        /// Computes the shared secret and the exchange hash. <paramref name="serverPublic"/> is Q_S (32 bytes);
        /// <paramref name="serverHostKeyBlob"/> is K_S (the full host-key string as received); <paramref name="clientId"/>
        /// / <paramref name="serverId"/> are the version strings (no CR LF); <paramref name="clientKexInit"/> /
        /// <paramref name="serverKexInit"/> are the exact KEXINIT payloads (type byte included).
        /// </summary>
        public void ComputeSharedAndHash(
            ReadOnlySpan<byte> serverPublic,
            ReadOnlySpan<byte> serverHostKeyBlob,
            string clientId, string serverId,
            ReadOnlySpan<byte> clientKexInit, ReadOnlySpan<byte> serverKexInit)
        {
            if (serverPublic.Length != 32) throw new SshProtocolException($"curve25519 server public value must be 32 bytes (got {serverPublic.Length}).");

            byte[] shared = _dh.DeriveSharedSecret(EphemeralPrivate, serverPublic);
            // Abort on the all-zero shared secret (RFC 8731 / RFC 7748 §6).
            bool allZero = true;
            foreach (byte b in shared) if (b != 0) { allZero = false; break; }
            if (allZero) throw new SshProtocolException("curve25519 produced an all-zero shared secret (invalid peer public value).");

            // The shared X is reinterpreted big-endian as K and encoded once as an mpint (length-prefix + sign byte);
            // both the exchange hash and the KDF feed this exact encoding.
            var kWriter = new SshWriter();
            kWriter.WriteMpint(shared);
            SharedSecretMpint = kWriter.ToArray();

            var hw = new SshWriter();
            hw.WriteString(Encoding.ASCII.GetBytes(clientId));
            hw.WriteString(Encoding.ASCII.GetBytes(serverId));
            hw.WriteString(clientKexInit);
            hw.WriteString(serverKexInit);
            hw.WriteString(serverHostKeyBlob);
            hw.WriteString(EphemeralPublic);
            hw.WriteString(serverPublic);
            hw.WriteMpint(shared);

            using var sha = SHA256.Create();
            ExchangeHash = sha.ComputeHash(hw.ToArray());
        }

        /// <summary>
        /// Derives <paramref name="length"/> bytes of key material for the per-letter key (RFC 4253 §7.2):
        /// <c>K1 = HASH(K || H || letter || session_id)</c>, then <c>K(n+1) = HASH(K || H || K1..Kn)</c>, the outputs
        /// concatenated and truncated. <paramref name="letter"/> is 'A'..'F'; <paramref name="sessionId"/> is the first
        /// exchange hash (= <see cref="ExchangeHash"/> for the first KEX).
        /// </summary>
        public byte[] DeriveKey(char letter, byte[] sessionId, int length)
        {
            using var sha = SHA256.Create();
            byte[] kMpint = SharedSecretMpint;

            // K1 = HASH(K || H || letter || session_id)
            byte[] k1 = sha.ComputeHash(Concat(kMpint, ExchangeHash, new[] { (byte)letter }, sessionId));
            var output = new List<byte>(k1);
            while (output.Count < length)
            {
                // K(n+1) = HASH(K || H || K1 || ... || Kn)
                byte[] next = sha.ComputeHash(Concat(kMpint, ExchangeHash, output.ToArray()));
                output.AddRange(next);
            }
            return output.GetRange(0, length).ToArray();
        }

        static byte[] Concat(params byte[][] parts)
        {
            int total = 0;
            foreach (byte[] p in parts) total += p.Length;
            byte[] result = new byte[total];
            int off = 0;
            foreach (byte[] p in parts) { Buffer.BlockCopy(p, 0, result, off, p.Length); off += p.Length; }
            return result;
        }
    }
}
