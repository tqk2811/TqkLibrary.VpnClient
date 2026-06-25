using System.Security.Cryptography;
using System.Text;

namespace TqkLibrary.VpnClient.Vtun.Auth
{
    /// <summary>
    /// vtun's password → key derivation (<c>prep_key</c> in <c>lfd_encrypt.c</c>, and the challenge key in <c>auth.c</c>).
    /// The shared secret string is run through MD5 to produce raw key bytes — no salt, no iteration count, no KDF:
    /// <list type="bullet">
    /// <item>a <b>16-byte</b> key is <c>MD5(password)</c> over the whole password (the challenge key, and the
    /// Blowfish-128 / AES-128 data-plane key);</item>
    /// <item>a <b>32-byte</b> key is <c>MD5(firstHalf) ‖ MD5(secondHalf)</c> — the password split at <c>len/2</c>
    /// (integer division), each half MD5'd into one 16-byte slot (the Blowfish-256 / AES-256 data-plane key).</item>
    /// </list>
    /// The password is taken as raw ASCII bytes (vtund MD5s the C string verbatim). ⚠️ Plain MD5 of the password is
    /// legacy/weak — it exists only to interoperate with the vtund daemon.
    /// </summary>
    public static class VtunKeyDerivation
    {
        /// <summary>The 16-byte challenge / 128-bit cipher key: <c>MD5(password)</c>.</summary>
        public static byte[] DeriveKey16(string password)
        {
            byte[] pwdBytes = Encoding.ASCII.GetBytes(password ?? string.Empty);
            using var md5 = MD5.Create();
            return md5.ComputeHash(pwdBytes);
        }

        /// <summary>
        /// The 32-byte (256-bit) cipher key: <c>MD5(password[0..len/2]) ‖ MD5(password[len/2..])</c>. Matches vtund's
        /// <c>prep_key</c> with <c>size == 32</c> (<c>halflen = strlen(passwd) &gt;&gt; 1</c>).
        /// </summary>
        public static byte[] DeriveKey32(string password)
        {
            byte[] pwdBytes = Encoding.ASCII.GetBytes(password ?? string.Empty);
            int halfLen = pwdBytes.Length >> 1;
            byte[] key = new byte[32];
            using var md5 = MD5.Create();
            byte[] first = md5.ComputeHash(pwdBytes, 0, halfLen);
            byte[] second = md5.ComputeHash(pwdBytes, halfLen, pwdBytes.Length - halfLen);
            first.CopyTo(key, 0);
            second.CopyTo(key, 16);
            return key;
        }

        /// <summary>Returns the cipher key for the given key size in bytes (16 or 32); throws for any other size.</summary>
        public static byte[] DeriveKey(string password, int keySizeInBytes) => keySizeInBytes switch
        {
            16 => DeriveKey16(password),
            32 => DeriveKey32(password),
            _ => throw new ArgumentOutOfRangeException(nameof(keySizeInBytes), keySizeInBytes, "vtun key size must be 16 or 32 bytes."),
        };
    }
}
