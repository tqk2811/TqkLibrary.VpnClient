using System.Text;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Vtun.Wire;

namespace TqkLibrary.VpnClient.Vtun.Auth
{
    /// <summary>
    /// The vtun challenge-response primitives (vtun's <c>auth.c</c>): the printable challenge encoding
    /// (<c>cl2cs</c>/<c>cs2cl</c>) and the password-keyed challenge transform (<c>encrypt_chal</c>).
    /// <list type="bullet">
    /// <item><b>Encoding</b> — each of the 16 challenge bytes becomes two letters from the alphabet
    /// <c>a..p</c> (a=0 … p=15: high nibble then low nibble), wrapped in <c>&lt; &gt;</c> ⇒ 34 chars. This is a custom
    /// 4-bit-per-char scheme, <b>not</b> base64 and <b>not</b> 0-9a-f hex.</item>
    /// <item><b>Transform</b> — the client proves it knows the password by Blowfish-ECB-encrypting the challenge with
    /// key = <c>MD5(password)</c> (two 8-byte blocks over the 16-byte challenge). This runs for <b>every</b> tunnel,
    /// independent of the data-plane <c>encrypt</c> setting.</item>
    /// </list>
    /// ⚠️ MD5 + Blowfish-ECB challenge auth is legacy/weak — present only to interoperate with the vtund daemon.
    /// </summary>
    public static class VtunChallengeCodec
    {
        const string Alphabet = "abcdefghijklmnop"; // index 0..15 → a..p

        /// <summary>
        /// Encodes a <see cref="VtunConstants.ChallengeSize"/>-byte challenge into vtun's printable form
        /// <c>&lt;xx..&gt;</c> (vtun's <c>cl2cs</c>).
        /// </summary>
        public static string Encode(ReadOnlySpan<byte> challenge)
        {
            if (challenge.Length != VtunConstants.ChallengeSize)
                throw new ArgumentException($"Challenge must be {VtunConstants.ChallengeSize} bytes.", nameof(challenge));

            var sb = new StringBuilder(VtunConstants.ChallengeSize * 2 + 2);
            sb.Append('<');
            for (int i = 0; i < challenge.Length; i++)
            {
                sb.Append(Alphabet[(challenge[i] & 0xf0) >> 4]);
                sb.Append(Alphabet[challenge[i] & 0x0f]);
            }
            sb.Append('>');
            return sb.ToString();
        }

        /// <summary>
        /// Decodes a vtun challenge string (the substring between the first <c>&lt;</c> and its <c>&gt;</c> must be
        /// exactly <c>32</c> letters from <c>a..p</c>) back into the 16 raw bytes (vtun's <c>cs2cl</c>). Returns
        /// <c>false</c> on a malformed string.
        /// </summary>
        public static bool TryDecode(string text, out byte[] challenge)
        {
            challenge = Array.Empty<byte>();
            if (text is null) return false;

            int open = text.IndexOf('<');
            if (open < 0) return false;
            int close = text.IndexOf('>', open + 1);
            if (close < 0) return false;

            string body = text.Substring(open + 1, close - open - 1);
            if (body.Length != VtunConstants.ChallengeSize * 2) return false;

            byte[] result = new byte[VtunConstants.ChallengeSize];
            for (int i = 0; i < VtunConstants.ChallengeSize; i++)
            {
                int hi = body[i * 2] - 'a';
                int lo = body[i * 2 + 1] - 'a';
                if (hi < 0 || hi > 15 || lo < 0 || lo > 15) return false;
                result[i] = (byte)((hi << 4) | lo);
            }
            challenge = result;
            return true;
        }

        /// <summary>
        /// Returns the challenge transformed for the response: Blowfish-ECB-encrypt the 16-byte
        /// <paramref name="challenge"/> with key = MD5(<paramref name="password"/>) (vtun's <c>encrypt_chal</c>). The
        /// password is taken as raw UTF-8/ASCII bytes (vtun MD5s the password string verbatim).
        /// </summary>
        public static byte[] EncryptChallenge(ReadOnlySpan<byte> challenge, string password)
        {
            if (challenge.Length != VtunConstants.ChallengeSize)
                throw new ArgumentException($"Challenge must be {VtunConstants.ChallengeSize} bytes.", nameof(challenge));

            byte[] key = DeriveKey(password);
            byte[] result = challenge.ToArray();
            var blowfish = new Blowfish(key);
            blowfish.EncryptEcb(result);
            return result;
        }

        /// <summary>The inverse of <see cref="EncryptChallenge"/> (vtun's <c>decrypt_chal</c>) — used by the test responder
        /// to verify a client's response.</summary>
        public static byte[] DecryptChallenge(ReadOnlySpan<byte> response, string password)
        {
            if (response.Length != VtunConstants.ChallengeSize)
                throw new ArgumentException($"Response must be {VtunConstants.ChallengeSize} bytes.", nameof(response));

            byte[] key = DeriveKey(password);
            byte[] result = response.ToArray();
            var blowfish = new Blowfish(key);
            blowfish.DecryptEcb(result);
            return result;
        }

        // vtun: BF_set_key(&key, 16, MD5(pwd, strlen(pwd), NULL)) — the Blowfish key is the raw 16-byte MD5 of the
        // password. Shared with the data-plane encryptor via VtunKeyDerivation (the same MD5(password) key material).
        static byte[] DeriveKey(string password) => VtunKeyDerivation.DeriveKey16(password);
    }
}
