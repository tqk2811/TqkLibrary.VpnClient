using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// A non-AEAD data cipher (AES-CBC) the client uses on an NCP-less server (the <c>cipher</c> directive, paired with
    /// <c>--auth</c>). Bundles the OpenVPN cipher name and the AES key length to slice from key2, plus a factory for the
    /// matching <see cref="IBlockCipher"/>. NCP only negotiates AEAD ciphers, so CBC appears only as the configured
    /// fallback (no NCP), mapped back from the <c>cipher</c> name via <see cref="TryResolve"/>.
    /// </summary>
    public sealed class OpenVpnCbcCipher
    {
        OpenVpnCbcCipher(string name, int keySizeBytes)
        {
            Name = name;
            KeySizeBytes = keySizeBytes;
        }

        /// <summary>The OpenVPN cipher name (e.g. <c>AES-128-CBC</c>).</summary>
        public string Name { get; }

        /// <summary>The AES cipher key length in bytes sliced from key2 (16 = AES-128, 24 = AES-192, 32 = AES-256).</summary>
        public int KeySizeBytes { get; }

        /// <summary>Creates a fresh AES-CBC block cipher (no padding — the data channel does its own PKCS7).</summary>
        public IBlockCipher CreateCipher() => new AesCbcCipher();

        /// <summary>AES-128-CBC (SoftEther's OpenVPN default data cipher).</summary>
        public static OpenVpnCbcCipher Aes128Cbc { get; } = new("AES-128-CBC", 16);

        /// <summary>AES-192-CBC.</summary>
        public static OpenVpnCbcCipher Aes192Cbc { get; } = new("AES-192-CBC", 24);

        /// <summary>AES-256-CBC.</summary>
        public static OpenVpnCbcCipher Aes256Cbc { get; } = new("AES-256-CBC", 32);

        /// <summary>The CBC ciphers this client can run as a fallback (NCP-less servers).</summary>
        public static IReadOnlyList<OpenVpnCbcCipher> Supported { get; } = new[] { Aes128Cbc, Aes192Cbc, Aes256Cbc };

        /// <summary>Resolves a cipher name (case-insensitive) to a supported AES-CBC descriptor.</summary>
        public static bool TryResolve(string? name, out OpenVpnCbcCipher cipher)
        {
            foreach (OpenVpnCbcCipher candidate in Supported)
                if (string.Equals(candidate.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    cipher = candidate;
                    return true;
                }
            cipher = Aes128Cbc;
            return false;
        }
    }
}
