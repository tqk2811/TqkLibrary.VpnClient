namespace TqkLibrary.Vpn.Crypto.Abstractions.Interfaces
{
    /// <summary>A keyed integrity/MAC algorithm with a (usually truncated) ICV, e.g. HMAC-SHA256-128 for ESP/IKE.</summary>
    public interface IIntegrityAlgo
    {
        /// <summary>Key length in bytes.</summary>
        int KeySizeInBytes { get; }

        /// <summary>Integrity Check Value length in bytes (the truncated MAC placed on the wire).</summary>
        int IcvSizeInBytes { get; }

        /// <summary>Computes the ICV over <paramref name="data"/> into <paramref name="icv"/> (length &gt;= <see cref="IcvSizeInBytes"/>).</summary>
        void ComputeIcv(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> icv);
    }
}
