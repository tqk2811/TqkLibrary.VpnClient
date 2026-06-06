namespace TqkLibrary.Vpn.Crypto.Abstractions.Interfaces
{
    /// <summary>A one-shot cryptographic hash (MD4, MD5, SHA-0/1/2...).</summary>
    public interface IHashAlgo
    {
        /// <summary>Digest length in bytes.</summary>
        int HashSizeInBytes { get; }

        /// <summary>Hashes <paramref name="input"/> into <paramref name="destination"/> (length &gt;= <see cref="HashSizeInBytes"/>).</summary>
        void ComputeHash(ReadOnlySpan<byte> input, Span<byte> destination);
    }
}
