using System.Security.Cryptography;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Ssh.Wire;

namespace TqkLibrary.VpnClient.Ssh.Transport
{
    /// <summary>
    /// Parses and verifies an <c>ssh-ed25519</c> server host key (RFC 8709). The host-key blob K_S is
    /// <c>string "ssh-ed25519" || string public_key(32)</c>; the signature blob over the exchange hash is
    /// <c>string "ssh-ed25519" || string signature(64)</c>. The server proves possession of the host key by signing the
    /// exchange hash H, which this verifies with <see cref="Ed25519Signer"/>. The SHA-256 fingerprint of K_S is exposed so
    /// a driver can pin the host key out of band (TOFU). No certificate chain — a raw key, as OpenSSH uses by default.
    /// </summary>
    public sealed class SshEd25519HostKey
    {
        const string Algorithm = "ssh-ed25519";

        readonly Ed25519Signer _signer = new();

        /// <summary>The 32-byte raw Ed25519 public key extracted from K_S.</summary>
        public byte[] PublicKey { get; }

        /// <summary>The full host-key blob K_S as received (kept for fingerprinting / pinning).</summary>
        public byte[] Blob { get; }

        SshEd25519HostKey(byte[] blob, byte[] publicKey)
        {
            Blob = blob;
            PublicKey = publicKey;
        }

        /// <summary>Parses an <c>ssh-ed25519</c> host-key blob K_S. Throws <see cref="SshProtocolException"/> on the wrong key type / length.</summary>
        public static SshEd25519HostKey Parse(ReadOnlySpan<byte> blob)
        {
            var r = new SshReader(blob);
            string alg = r.ReadStringUtf8();
            if (alg != Algorithm) throw new SshProtocolException($"Unsupported host-key algorithm '{alg}' (expected ssh-ed25519).");
            byte[] pub = r.ReadStringBytes();
            if (pub.Length != 32) throw new SshProtocolException($"ssh-ed25519 host key must be 32 bytes (got {pub.Length}).");
            return new SshEd25519HostKey(blob.ToArray(), pub);
        }

        /// <summary>
        /// Verifies <paramref name="signatureBlob"/> (the KEX_ECDH_REPLY signature: <c>string "ssh-ed25519" || string
        /// sig(64)</c>) over the exchange hash <paramref name="exchangeHash"/>. Returns true iff the host key signed H.
        /// </summary>
        public bool VerifyExchangeHash(ReadOnlySpan<byte> signatureBlob, ReadOnlySpan<byte> exchangeHash)
        {
            var r = new SshReader(signatureBlob);
            string alg = r.ReadStringUtf8();
            if (alg != Algorithm) return false;
            byte[] sig = r.ReadStringBytes();
            if (sig.Length != 64) return false;
            return _signer.Verify(PublicKey, exchangeHash, sig);
        }

        /// <summary>The OpenSSH-style SHA-256 fingerprint of K_S (base64, no padding) — e.g. for host-key pinning logs.</summary>
        public string Sha256Fingerprint()
        {
            using var sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(Blob);
            return "SHA256:" + Convert.ToBase64String(hash).TrimEnd('=');
        }
    }
}
