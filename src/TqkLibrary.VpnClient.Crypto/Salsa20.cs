// Alias the one BouncyCastle type rather than importing Org.BouncyCastle.* wholesale (its Crypto namespace defines
// types — IAeadCipher, etc. — that clash with this project's interfaces; see Curve25519DhGroup / Ed25519Signer for
// the same aliasing pattern). The BCL ships no Salsa20 on either target framework, so BouncyCastle is used on net8.0
// and netstandard2.0 alike (no #if split).
using Salsa20Engine = Org.BouncyCastle.Crypto.Engines.Salsa20Engine;
using KeyParameter = Org.BouncyCastle.Crypto.Parameters.KeyParameter;
using ParametersWithIV = Org.BouncyCastle.Crypto.Parameters.ParametersWithIV;

namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// Salsa20 stream cipher (Bernstein, eSTREAM). The round count is a constructor parameter so both the standard
    /// 20-round Salsa20/20 and the reduced 12-round Salsa20/12 are available from one type: ZeroTier (V.7.3) encrypts
    /// VL1 packets with <b>Salsa20/12</b> and derives node addresses with a memory-hard hash built on <b>Salsa20/20</b>.
    /// <para>
    /// Fixed sizes: 32-byte (256-bit) key and 8-byte nonce/IV (the eSTREAM convention). Encryption and decryption are
    /// the same XOR-with-keystream operation. Each call starts a fresh stream at counter 0 — callers needing a
    /// continued keystream across multiple buffers should request one larger buffer instead.
    /// </para>
    /// Backed by BouncyCastle's <c>Salsa20Engine(rounds)</c> on both target frameworks; verified byte-exact against the
    /// ECRYPT eSTREAM test vectors (see Salsa20Tests). Salsa20 is the basis of ChaCha20 but is <b>not</b> interchangeable
    /// with it.
    /// </summary>
    public sealed class Salsa20
    {
        /// <summary>Salsa20 256-bit key length in bytes.</summary>
        public const int KeyBytes = 32;

        /// <summary>Salsa20 nonce/IV length in bytes (eSTREAM convention).</summary>
        public const int NonceBytes = 8;

        readonly int _rounds;

        /// <summary>Creates a Salsa20 cipher with the given (even) round count: 20 for Salsa20/20, 12 for Salsa20/12.</summary>
        public Salsa20(int rounds = 20)
        {
            if (rounds < 2 || (rounds & 1) != 0)
                throw new ArgumentException("Salsa20 round count must be a positive even number (e.g. 20 or 12).", nameof(rounds));
            _rounds = rounds;
        }

        /// <summary>Number of rounds this instance runs (20 = Salsa20/20, 12 = Salsa20/12).</summary>
        public int Rounds => _rounds;

        /// <summary>
        /// XORs <paramref name="input"/> with the Salsa20 keystream (started at counter 0) into
        /// <paramref name="output"/> (same length). Decryption is the identical call.
        /// </summary>
        public void Transform(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (key.Length != KeyBytes) throw new ArgumentException($"Salsa20 key must be {KeyBytes} bytes.", nameof(key));
            if (nonce.Length != NonceBytes) throw new ArgumentException($"Salsa20 nonce must be {NonceBytes} bytes.", nameof(nonce));
            if (output.Length < input.Length) throw new ArgumentException("output too small", nameof(output));

            var engine = new Salsa20Engine(_rounds);
            engine.Init(true, new ParametersWithIV(new KeyParameter(key.ToArray()), nonce.ToArray()));

            byte[] inBytes = input.ToArray();
            byte[] outBytes = new byte[inBytes.Length];
            engine.ProcessBytes(inBytes, 0, inBytes.Length, outBytes, 0);
            outBytes.AsSpan(0, input.Length).CopyTo(output);
        }

        /// <summary>Fills <paramref name="output"/> with raw keystream bytes (equivalent to encrypting zeros).</summary>
        public void GenerateKeystream(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, Span<byte> output)
        {
            // ToArray() of an empty span is fine; Transform XORs against zeros.
            byte[] zeros = new byte[output.Length];
            Transform(key, nonce, zeros, output);
        }

        /// <summary>
        /// Opens a <see cref="Stream"/> that keeps the Salsa20 keystream position across multiple
        /// <see cref="Stream.Process"/> calls (the counter advances; it is <b>not</b> reset per call). This is what a
        /// CBC-like sequential keystream needs — e.g. ZeroTier's memory-hard address hash encrypts a 2 MB buffer in
        /// 64-byte blocks and then re-encrypts the running digest, all on one continuous stream.
        /// </summary>
        public Stream CreateStream(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
        {
            if (key.Length != KeyBytes) throw new ArgumentException($"Salsa20 key must be {KeyBytes} bytes.", nameof(key));
            if (nonce.Length != NonceBytes) throw new ArgumentException($"Salsa20 nonce must be {NonceBytes} bytes.", nameof(nonce));

            var engine = new Salsa20Engine(_rounds);
            engine.Init(true, new ParametersWithIV(new KeyParameter(key.ToArray()), nonce.ToArray()));
            return new Stream(engine);
        }

        /// <summary>
        /// A stateful Salsa20 keystream whose counter is preserved across calls. Created by
        /// <see cref="Salsa20.CreateStream"/>; each <see cref="Process"/> continues the same keystream.
        /// </summary>
        public sealed class Stream
        {
            readonly Salsa20Engine _engine;

            internal Stream(Salsa20Engine engine) => _engine = engine;

            /// <summary>XORs <paramref name="data"/> in place with the next keystream bytes, advancing the counter.</summary>
            public void Process(Span<byte> data)
            {
                byte[] buf = data.ToArray();
                byte[] outBuf = new byte[buf.Length];
                _engine.ProcessBytes(buf, 0, buf.Length, outBuf, 0);
                outBuf.AsSpan(0, data.Length).CopyTo(data);
            }
        }
    }
}
