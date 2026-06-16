using System.Text;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.VpnClient.SoftEther
{
    /// <summary>
    /// SoftEther password authentication codec. Computes the on-wire <c>secure_password</c> the client puts in its
    /// <c>login</c> PACK, so the plaintext password never crosses the wire. Two-stage SHA-0 (re-implemented from the
    /// protocol behavior, spec doc <c>07</c> — not copied from the GPL source):
    /// <list type="number">
    /// <item><c>HashedPassword = SHA0(password_ansi ‖ UPPER(username)_ansi)</c> — a stored, server-side-comparable hash.</item>
    /// <item><c>SecurePassword = SHA0(HashedPassword ‖ server_random)</c> — mixes the per-session 20-byte challenge.</item>
    /// </list>
    /// The hash is pluggable via <see cref="IHashAlgo"/> (a SHA-0 instance — <c>Crypto.Sha0</c>) so this stays an
    /// instance type that is trivial to test with a known vector. Strings are encoded as 8-bit ANSI (Latin-1),
    /// matching the SoftEther <c>VALUE_STR</c> convention; the username is upper-cased with the invariant culture.
    /// </summary>
    public sealed class SoftEtherAuth
    {
        readonly IHashAlgo _sha0;

        /// <summary>Creates an authenticator over the given SHA-0 implementation (must produce a 20-byte digest).</summary>
        public SoftEtherAuth(IHashAlgo sha0)
        {
            _sha0 = sha0 ?? throw new ArgumentNullException(nameof(sha0));
            if (_sha0.HashSizeInBytes != SoftEtherProtocol.RandomSize)
                throw new ArgumentException(
                    $"SoftEther auth needs a {SoftEtherProtocol.RandomSize}-byte hash (SHA-0); got {_sha0.HashSizeInBytes}.",
                    nameof(sha0));
        }

        /// <summary>
        /// Computes <c>HashedPassword = SHA0(password ‖ UPPER(username))</c>. This is the value a server stores for the
        /// account; it does not depend on the per-session challenge, so it can be precomputed.
        /// </summary>
        public byte[] HashPassword(string password, string username)
        {
            if (password is null) throw new ArgumentNullException(nameof(password));
            if (username is null) throw new ArgumentNullException(nameof(username));

            byte[] passwordBytes = Ansi(password);
            byte[] upperUser = Ansi(username.ToUpperInvariant());
            var input = new byte[passwordBytes.Length + upperUser.Length];
            Buffer.BlockCopy(passwordBytes, 0, input, 0, passwordBytes.Length);
            Buffer.BlockCopy(upperUser, 0, input, passwordBytes.Length, upperUser.Length);

            var digest = new byte[_sha0.HashSizeInBytes];
            _sha0.ComputeHash(input, digest);
            return digest;
        }

        /// <summary>
        /// Computes the on-wire <c>SecurePassword = SHA0(HashedPassword ‖ serverRandom)</c> from a pre-computed
        /// <paramref name="hashedPassword"/> (20 bytes from <see cref="HashPassword"/>) and the 20-byte server challenge.
        /// </summary>
        public byte[] SecureFromHashedPassword(ReadOnlySpan<byte> hashedPassword, ReadOnlySpan<byte> serverRandom)
        {
            if (hashedPassword.Length != _sha0.HashSizeInBytes)
                throw new ArgumentException($"hashedPassword must be {_sha0.HashSizeInBytes} bytes.", nameof(hashedPassword));
            if (serverRandom.Length != SoftEtherProtocol.RandomSize)
                throw new ArgumentException($"serverRandom must be {SoftEtherProtocol.RandomSize} bytes.", nameof(serverRandom));

            var input = new byte[hashedPassword.Length + serverRandom.Length];
            hashedPassword.CopyTo(input);
            serverRandom.CopyTo(input.AsSpan(hashedPassword.Length));

            var digest = new byte[_sha0.HashSizeInBytes];
            _sha0.ComputeHash(input, digest);
            return digest;
        }

        /// <summary>
        /// One-shot: computes the on-wire <c>secure_password</c> straight from the plaintext credentials and the
        /// server challenge. Convenience over <see cref="HashPassword"/> + <see cref="SecureFromHashedPassword"/>.
        /// </summary>
        public byte[] ComputeSecurePassword(string password, string username, ReadOnlySpan<byte> serverRandom)
            => SecureFromHashedPassword(HashPassword(password, username), serverRandom);

        static byte[] Ansi(string value)
        {
            // SoftEther treats these strings as 8-bit ANSI (low byte of each char), matching VALUE_STR on the wire.
            var bytes = new byte[value.Length];
            for (int i = 0; i < value.Length; i++)
                bytes[i] = (byte)value[i];
            return bytes;
        }
    }
}
