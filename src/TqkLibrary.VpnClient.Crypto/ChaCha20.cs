// Alias the one BouncyCastle type rather than importing Org.BouncyCastle.* wholesale (its Crypto namespace defines
// types — IAeadCipher, etc. — that clash with this project's interfaces; see Curve25519DhGroup / Ed25519Signer / Salsa20
// for the same aliasing pattern). The BCL ships no raw ChaCha20 stream cipher on either target framework, so BouncyCastle
// is used on net8.0 and netstandard2.0 alike (no #if split).
using ChaChaEngine = Org.BouncyCastle.Crypto.Engines.ChaChaEngine;
using KeyParameter = Org.BouncyCastle.Crypto.Parameters.KeyParameter;
using ParametersWithIV = Org.BouncyCastle.Crypto.Parameters.ParametersWithIV;

namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// ChaCha20 stream cipher (Bernstein) in its <b>original</b> form: a 32-byte (256-bit) key, an 8-byte nonce and a
    /// 64-bit block counter (the djb layout — <b>not</b> the IETF RFC 8439 layout, which uses a 12-byte nonce and a
    /// 32-bit counter and is therefore not interchangeable). Each 64-byte block advances the counter by one starting from
    /// zero.
    /// <para>
    /// This is the primitive OpenSSH's <c>chacha20-poly1305@openssh.com</c> AEAD is built on (PROTOCOL.chacha20poly1305):
    /// the packet length is encrypted under one key at counter 0, and a per-packet Poly1305 key is taken from the first
    /// 32 bytes of keystream (counter 0) before the payload is encrypted from counter 1 on. Use <see cref="CreateStream"/>
    /// to obtain a continuous keystream whose counter is preserved across calls (counter-0 block → Poly1305 key, then the
    /// same stream continues into the payload at counter 1), mirroring <see cref="Salsa20.Stream"/>.
    /// </para>
    /// Backed by BouncyCastle's <c>ChaChaEngine</c> (20 rounds) on both target frameworks.
    /// </summary>
    public sealed class ChaCha20
    {
        /// <summary>ChaCha20 256-bit key length in bytes.</summary>
        public const int KeyBytes = 32;

        /// <summary>ChaCha20 (original djb) nonce length in bytes.</summary>
        public const int NonceBytes = 8;

        /// <summary>
        /// XORs <paramref name="input"/> with the ChaCha20 keystream (started at block counter 0) into
        /// <paramref name="output"/> (same length). Decryption is the identical call.
        /// </summary>
        public void Transform(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (output.Length < input.Length) throw new ArgumentException("output too small", nameof(output));
            var stream = CreateStream(key, nonce);
            input.CopyTo(output.Slice(0, input.Length));
            stream.Process(output.Slice(0, input.Length));
        }

        /// <summary>
        /// Opens a <see cref="Stream"/> that keeps the ChaCha20 keystream position across multiple
        /// <see cref="Stream.Process"/> / <see cref="Stream.Skip"/> calls (the counter advances; it is <b>not</b> reset
        /// per call). This is what the OpenSSH AEAD needs: read the counter-0 block for the Poly1305 key, then continue
        /// the same stream into the payload at counter 1.
        /// </summary>
        public Stream CreateStream(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
        {
            if (key.Length != KeyBytes) throw new ArgumentException($"ChaCha20 key must be {KeyBytes} bytes.", nameof(key));
            if (nonce.Length != NonceBytes) throw new ArgumentException($"ChaCha20 nonce must be {NonceBytes} bytes.", nameof(nonce));

            var engine = new ChaChaEngine();
            engine.Init(true, new ParametersWithIV(new KeyParameter(key.ToArray()), nonce.ToArray()));
            return new Stream(engine);
        }

        /// <summary>
        /// A stateful ChaCha20 keystream whose counter is preserved across calls. Created by
        /// <see cref="ChaCha20.CreateStream"/>; each <see cref="Process"/>/<see cref="Skip"/> continues the same keystream.
        /// </summary>
        public sealed class Stream
        {
            readonly ChaChaEngine _engine;

            internal Stream(ChaChaEngine engine) => _engine = engine;

            /// <summary>XORs <paramref name="data"/> in place with the next keystream bytes, advancing the counter.</summary>
            public void Process(Span<byte> data)
            {
                byte[] buf = data.ToArray();
                byte[] outBuf = new byte[buf.Length];
                _engine.ProcessBytes(buf, 0, buf.Length, outBuf, 0);
                outBuf.AsSpan(0, data.Length).CopyTo(data);
            }

            /// <summary>Writes the next <paramref name="destination"/>.Length keystream bytes (XOR against zeros), advancing the counter.</summary>
            public void NextKeystream(Span<byte> destination)
            {
                for (int i = 0; i < destination.Length; i++) destination[i] = 0;
                Process(destination);
            }

            /// <summary>Discards <paramref name="count"/> keystream bytes (advances the counter without producing output).</summary>
            public void Skip(int count)
            {
                if (count <= 0) return;
                Span<byte> scratch = count <= 256 ? stackalloc byte[count] : new byte[count];
                Process(scratch);
            }
        }
    }
}
