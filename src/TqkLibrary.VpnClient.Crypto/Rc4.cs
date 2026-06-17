namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// RC4 stream cipher (Rivest, 1987) — the keystream generator MPPE (RFC 3078) builds on. The cipher is a
    /// keyed permutation of 0..255 (KSA) feeding a pseudo-random byte stream (PRGA) that is XORed with the data;
    /// encryption and decryption are the same operation.
    /// <para>
    /// RC4 is cryptographically broken (biased keystream, RFC 7465 prohibits it in TLS) — provided <b>only</b>
    /// for legacy MPPE/PPTP and SoftEther <c>use_encrypt</c> compatibility, never for new designs.
    /// </para>
    /// </summary>
    public sealed class Rc4
    {
        readonly byte[] _s = new byte[256];
        int _i;
        int _j;

        /// <summary>Initializes the cipher state from <paramref name="key"/> (1..256 bytes) via the RC4 key-scheduling algorithm.</summary>
        public Rc4(ReadOnlySpan<byte> key)
        {
            if (key.Length == 0 || key.Length > 256)
                throw new ArgumentException("RC4 key must be 1..256 bytes", nameof(key));

            for (int i = 0; i < 256; i++) _s[i] = (byte)i;
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + _s[i] + key[i % key.Length]) & 0xff;
                (_s[i], _s[j]) = (_s[j], _s[i]);
            }
            _i = 0;
            _j = 0;
        }

        /// <summary>
        /// XORs <paramref name="input"/> with the next keystream bytes into <paramref name="output"/> (same length),
        /// advancing the cipher state. Calling repeatedly continues the same keystream.
        /// </summary>
        public void Process(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (output.Length < input.Length) throw new ArgumentException("output too small", nameof(output));
            for (int n = 0; n < input.Length; n++)
                output[n] = (byte)(input[n] ^ NextKeystreamByte());
        }

        /// <summary>Fills <paramref name="output"/> with raw keystream bytes (equivalent to encrypting zeros).</summary>
        public void GenerateKeystream(Span<byte> output)
        {
            for (int n = 0; n < output.Length; n++)
                output[n] = NextKeystreamByte();
        }

        byte NextKeystreamByte()
        {
            _i = (_i + 1) & 0xff;
            _j = (_j + _s[_i]) & 0xff;
            (_s[_i], _s[_j]) = (_s[_j], _s[_i]);
            return _s[(_s[_i] + _s[_j]) & 0xff];
        }

        /// <summary>Convenience one-shot: RC4-transforms <paramref name="data"/> under <paramref name="key"/> and returns a new array.</summary>
        public static byte[] Apply(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
        {
            var output = new byte[data.Length];
            new Rc4(key).Process(data, output);
            return output;
        }
    }
}
