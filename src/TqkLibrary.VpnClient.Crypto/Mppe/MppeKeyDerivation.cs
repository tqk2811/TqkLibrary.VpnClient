using TqkLibrary.VpnClient.Crypto.Mppe.Enums;

namespace TqkLibrary.VpnClient.Crypto.Mppe
{
    /// <summary>
    /// MPPE session-key derivation (RFC 3078 §7 + RFC 3079) — the SHA-1/RC4 key schedule that turns the
    /// MS-CHAPv2 MPPE start keys into RC4 session keys and re-keys them as the protocol runs.
    /// <para>
    /// Two stages, both used by <see cref="MppeSession"/>:
    /// </para>
    /// <list type="bullet">
    ///   <item><b>Initial key</b> — <c>GetNewKeyFromSHA(StartKey, StartKey, len)</c> then strength reduction
    ///   (RFC 3079 §3.1); the SHA digest is used directly (no RC4 pass) for the very first session key.</item>
    ///   <item><b>Re-key</b> — <c>InterimKey = GetNewKeyFromSHA(StartKey, CurrentSessionKey, len)</c>, then
    ///   <c>NewKey = RC4(InterimKey, InterimKey)</c>, then strength reduction (RFC 3078 §7.3).</item>
    /// </list>
    /// SHA-1 (in the BCL) is used — <b>not</b> SHA-0; MPPE pre-dates the SHA-0 → SHA-1 fix and uses the FIPS 180-1 SHA-1.
    /// </summary>
    public static class MppeKeyDerivation
    {
        // RFC 3078 §7.3 / RFC 3079 §3.3: SHApad1 = 40 × 0x00, SHApad2 = 40 × 0xF2.
        static readonly byte[] ShaPad1 = new byte[40];
        static readonly byte[] ShaPad2 = CreatePad2();

        static byte[] CreatePad2()
        {
            var pad = new byte[40];
            for (int i = 0; i < 40; i++) pad[i] = 0xF2;
            return pad;
        }

        /// <summary>RC4 session-key length in bytes for a given strength: 8 for 40/56-bit, 16 for 128-bit.</summary>
        public static int SessionKeyLength(MppeKeyStrength strength)
            => strength == MppeKeyStrength.Bits128 ? 16 : 8;

        /// <summary>
        /// <c>GetNewKeyFromSHA</c> (RFC 3078 §7.3): <c>InterimKey = SHA1(StartKey || SHApad1 || SessionKey || SHApad2)</c>
        /// truncated to <paramref name="keyLength"/>. Both keys are the same length (<paramref name="keyLength"/>).
        /// </summary>
        public static byte[] GetNewKeyFromSha(byte[] startKey, byte[] currentSessionKey, int keyLength)
        {
            using var sha1 = System.Security.Cryptography.SHA1.Create();
            sha1.TransformBlock(startKey, 0, keyLength, null, 0);
            sha1.TransformBlock(ShaPad1, 0, 40, null, 0);
            sha1.TransformBlock(currentSessionKey, 0, keyLength, null, 0);
            sha1.TransformFinalBlock(ShaPad2, 0, 40);

            var interim = new byte[keyLength];
            Buffer.BlockCopy(sha1.Hash!, 0, interim, 0, keyLength);
            return interim;
        }

        /// <summary>
        /// Initial RC4 session key (RFC 3079 §3.1): <c>GetNewKeyFromSHA(StartKey, StartKey, len)</c> then
        /// <see cref="ReduceStrength"/>. The SHA digest is used directly (no RC4 re-encryption on the first key).
        /// </summary>
        public static byte[] DeriveInitialSessionKey(byte[] startKey, MppeKeyStrength strength)
        {
            int len = SessionKeyLength(strength);
            byte[] key = GetNewKeyFromSha(startKey, startKey, len);
            ReduceStrength(key, strength);
            return key;
        }

        /// <summary>
        /// Re-keys to the next RC4 session key (RFC 3078 §7.3): SHA interim from <paramref name="startKey"/> and the
        /// current key, then RC4-encrypt the interim key with itself, then <see cref="ReduceStrength"/>.
        /// </summary>
        public static byte[] DeriveNextSessionKey(byte[] startKey, byte[] currentSessionKey, MppeKeyStrength strength)
        {
            int len = SessionKeyLength(strength);
            byte[] interim = GetNewKeyFromSha(startKey, currentSessionKey, len);

            // SessionKey = RC4(InterimKey, InterimKey) — re-encrypt the interim key with itself (RFC 3078 §7.3).
            byte[] next = Rc4.Apply(interim, interim);
            ReduceStrength(next, strength);
            return next;
        }

        /// <summary>
        /// Applies the fixed-prefix strength reduction in place (RFC 3078 §7.3 / RFC 3079 §2): 40-bit ⇒ first three
        /// octets become 0xD1 0x26 0x9E; 56-bit ⇒ first octet becomes 0xD1; 128-bit ⇒ unchanged.
        /// </summary>
        public static void ReduceStrength(byte[] sessionKey, MppeKeyStrength strength)
        {
            switch (strength)
            {
                case MppeKeyStrength.Bits40:
                    sessionKey[0] = 0xD1;
                    sessionKey[1] = 0x26;
                    sessionKey[2] = 0x9E;
                    break;
                case MppeKeyStrength.Bits56:
                    sessionKey[0] = 0xD1;
                    break;
                case MppeKeyStrength.Bits128:
                    break; // no reduction
            }
        }
    }
}
