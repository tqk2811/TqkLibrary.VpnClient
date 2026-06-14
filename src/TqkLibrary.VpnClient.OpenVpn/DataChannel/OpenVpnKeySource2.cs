using System.Security.Cryptography;

namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// One side's random key material for OpenVPN key-method-2. The client contributes a 48-byte pre-master secret
    /// plus two 32-byte randoms; the server contributes only the two randoms (its <see cref="PreMaster"/> is empty).
    /// Both sides combine the two key sources to derive the data-channel keys (see <see cref="OpenVpnKeyMethod2"/>).
    /// </summary>
    public sealed class OpenVpnKeySource2
    {
        /// <summary>Pre-master secret length (client only).</summary>
        public const int PreMasterSize = 48;

        /// <summary>Each random's length.</summary>
        public const int RandomSize = 32;

        /// <summary>Creates a key source from its parts (<paramref name="preMaster"/> empty for the server side).</summary>
        public OpenVpnKeySource2(byte[] preMaster, byte[] random1, byte[] random2)
        {
            PreMaster = preMaster ?? throw new ArgumentNullException(nameof(preMaster));
            Random1 = random1 ?? throw new ArgumentNullException(nameof(random1));
            Random2 = random2 ?? throw new ArgumentNullException(nameof(random2));
            if (Random1.Length != RandomSize || Random2.Length != RandomSize)
                throw new ArgumentException($"each random must be {RandomSize} bytes.");
            if (PreMaster.Length != 0 && PreMaster.Length != PreMasterSize)
                throw new ArgumentException($"pre-master must be 0 or {PreMasterSize} bytes.", nameof(preMaster));
        }

        /// <summary>The 48-byte pre-master (client) or an empty array (server).</summary>
        public byte[] PreMaster { get; }

        /// <summary>The first 32-byte random (feeds the master-secret seed).</summary>
        public byte[] Random1 { get; }

        /// <summary>The second 32-byte random (feeds the key-expansion seed).</summary>
        public byte[] Random2 { get; }

        /// <summary>Generates a fresh client key source (pre-master + both randoms) from the system RNG.</summary>
        public static OpenVpnKeySource2 GenerateClient()
        {
            byte[] pre = new byte[PreMasterSize];
            byte[] r1 = new byte[RandomSize];
            byte[] r2 = new byte[RandomSize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(pre);
            rng.GetBytes(r1);
            rng.GetBytes(r2);
            return new OpenVpnKeySource2(pre, r1, r2);
        }
    }
}
