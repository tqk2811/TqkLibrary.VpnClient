namespace TqkLibrary.VpnClient.Drivers.AmneziaWg.Interfaces
{
    /// <summary>
    /// The source of randomness the AmneziaWG obfuscator draws on for junk bytes and junk-packet sizes. Injectable so a
    /// deterministic fake can pin exact sizes and byte content in tests; the default (<see cref="Helpers.CryptoAmneziaWgRandom"/>)
    /// draws from <see cref="System.Security.Cryptography.RandomNumberGenerator"/> so real junk is unpredictable to a DPI.
    /// </summary>
    public interface IAmneziaWgRandom
    {
        /// <summary>Returns <paramref name="count"/> fresh random bytes (may be zero-length when <paramref name="count"/> is 0).</summary>
        byte[] NextBytes(int count);

        /// <summary>Returns a random integer in the inclusive range [<paramref name="minInclusive"/>, <paramref name="maxInclusive"/>].</summary>
        int NextInt(int minInclusive, int maxInclusive);
    }
}
