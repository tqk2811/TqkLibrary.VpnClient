using System.Buffers.Binary;
using System.Collections.Generic;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.SoftEther.DataChannel
{
    /// <summary>
    /// Reads one SoftEther data <b>block</b> at a time off an <see cref="IByteStreamTransport"/>, reassembling it across
    /// partial TLS reads. A block is self-describing — <c>uint32(num_frames)</c> then, per frame, <c>uint32(size)</c> and
    /// the frame bytes — so the reader pulls each length-prefixed piece in turn rather than knowing the total up front.
    /// A frame count of <see cref="SoftEtherDataConstants.KeepAliveMagic"/> (<c>0xFFFFFFFF</c>) instead marks a
    /// keep-alive block (<c>uint32(magic) · uint32(size) · size bytes</c>): the reader consumes and discards it, then
    /// reads on, so an idle peer's keep-alives never surface as frames nor as a phantom close. A clean EOF before any
    /// byte of a new block surfaces as an empty result so the caller can treat it as the peer closing the session.
    /// </summary>
    public sealed class SoftEtherDataBlockReader
    {
        readonly IByteStreamTransport _transport;

        /// <summary>Creates a reader over <paramref name="transport"/> (already connected + TLS-established).</summary>
        public SoftEtherDataBlockReader(IByteStreamTransport transport)
            => _transport = transport ?? throw new ArgumentNullException(nameof(transport));

        /// <summary>
        /// Reads the next data block and returns its frames, transparently consuming any keep-alive blocks in between, or
        /// an empty list if the peer closed the stream cleanly at a block boundary. Throws <see cref="FormatException"/>
        /// on a malformed block and <see cref="SoftEtherProtocolException"/> if the stream ends mid-block.
        /// </summary>
        public async ValueTask<IReadOnlyList<byte[]>> ReadBlockAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                byte[]? countBytes = await ReadExactlyOrEofAsync(SoftEtherDataFrameCodec.CountPrefixLength, cancellationToken).ConfigureAwait(false);
                if (countBytes is null)
                    return Array.Empty<byte[]>();   // clean EOF at a block boundary

                uint count = BinaryPrimitives.ReadUInt32BigEndian(countBytes);

                // Keep-alive block: uint32(size) + size random bytes — read and discard, then read the next block.
                if (count == SoftEtherDataConstants.KeepAliveMagic)
                {
                    byte[] kaSizeBytes = await ReadExactlyAsync(SoftEtherDataFrameCodec.SizePrefixLength, cancellationToken).ConfigureAwait(false);
                    uint kaSize = BinaryPrimitives.ReadUInt32BigEndian(kaSizeBytes);
                    if (kaSize > SoftEtherDataConstants.MaxKeepAliveSize)
                        throw new FormatException($"SoftEther keep-alive declares {kaSize} bytes, over the {SoftEtherDataConstants.MaxKeepAliveSize} limit.");
                    if (kaSize != 0)
                        _ = await ReadExactlyAsync((int)kaSize, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                if (count > SoftEtherDataConstants.MaxFramesPerBlock)
                    throw new FormatException($"SoftEther data block declares {count} frames, over the {SoftEtherDataConstants.MaxFramesPerBlock} limit.");

                var frames = new List<byte[]>((int)count);
                for (uint i = 0; i < count; i++)
                {
                    byte[] sizeBytes = await ReadExactlyAsync(SoftEtherDataFrameCodec.SizePrefixLength, cancellationToken).ConfigureAwait(false);
                    uint size = BinaryPrimitives.ReadUInt32BigEndian(sizeBytes);
                    if (size > SoftEtherDataConstants.MaxFrameSize)
                        throw new FormatException($"SoftEther data frame declares {size} bytes, over the {SoftEtherDataConstants.MaxFrameSize} limit.");
                    frames.Add(size == 0 ? Array.Empty<byte>() : await ReadExactlyAsync((int)size, cancellationToken).ConfigureAwait(false));
                }
                // A genuine data block with zero frames is a valid no-op (a flush); loop to read the next real block.
                if (frames.Count == 0)
                    continue;
                return frames;
            }
        }

        // Reads exactly count bytes; a 0-byte read mid-buffer is a half-open stream → protocol error.
        async ValueTask<byte[]> ReadExactlyAsync(int count, CancellationToken cancellationToken)
        {
            byte[]? buffer = await ReadExactlyOrEofAsync(count, cancellationToken).ConfigureAwait(false);
            if (buffer is null)
                throw new SoftEtherProtocolException("SoftEther data stream ended in the middle of a block.");
            return buffer;
        }

        // Reads exactly count bytes, or returns null if the very first read sees EOF (clean close at a boundary).
        async ValueTask<byte[]?> ReadExactlyOrEofAsync(int count, CancellationToken cancellationToken)
        {
            var buffer = new byte[count];
            int filled = 0;
            while (filled < count)
            {
                int read = await _transport.ReadAsync(new Memory<byte>(buffer, filled, count - filled), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    return filled == 0 ? (byte[]?)null : throw new SoftEtherProtocolException("SoftEther data stream ended in the middle of a block.");
                filled += read;
            }
            return buffer;
        }
    }
}
