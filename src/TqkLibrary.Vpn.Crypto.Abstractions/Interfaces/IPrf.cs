namespace TqkLibrary.Vpn.Crypto.Abstractions.Interfaces
{
    /// <summary>A pseudo-random function (e.g. HMAC-SHA256) used for IKE/PPP key derivation.</summary>
    public interface IPrf
    {
        /// <summary>Native output size in bytes (one PRF block).</summary>
        int OutputSizeInBytes { get; }

        /// <summary>Computes PRF(key, seed) into <paramref name="output"/> (one block).</summary>
        void Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> seed, Span<byte> output);
    }
}
