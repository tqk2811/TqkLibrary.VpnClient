using System;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.GtpU
{
    /// <summary>
    /// An <see cref="IDatagramTransport"/> decorator that adds/strips the GTP-U header (3GPP TS 29.281) around an inner UDP
    /// pipe, so the reused <c>RawIpPassthroughChannel</c> above needs no GTP-U awareness — it just sees a raw inner IP
    /// packet in each direction. <b>Outbound</b> wraps the inner IP packet in a G-PDU (message type 255) stamped with the
    /// configured TEID (and, when sequence numbers are enabled, an incrementing 16-bit Sequence Number). <b>Inbound</b>
    /// decodes the datagram via <see cref="GtpUHeader.TryDecode"/>, keeps only a <b>G-PDU</b> whose TEID matches the
    /// expected inbound TEID (when one is configured), strips the header + optional block + extension headers, and surfaces
    /// only the inner IP payload; anything else — a malformed/short/wrong-version datagram, an Echo Request/Response, an
    /// Error Indication, any other message type, a mismatched TEID or a header-only datagram — is <b>dropped</b> by
    /// returning 0 length, which the channel's receive loop treats as "nothing to deliver".
    /// <para>GTP-U is a plain tunnel: it does <b>not</b> encrypt or authenticate the payload — it only tags it with a TEID.</para>
    /// </summary>
    internal sealed class GtpUFramingTransport : IDatagramTransport
    {
        readonly IDatagramTransport _inner;
        readonly uint _teid;
        readonly uint? _expectedInboundTeid;
        readonly bool _enableSequence;
        int _sequenceNumber; // incremented per sent G-PDU; wraps at 16 bits when written to the header
        byte[]? _receiveScratch;

        /// <summary>
        /// Wraps <paramref name="inner"/>, stamping outbound G-PDUs with <paramref name="teid"/>. When
        /// <paramref name="expectedInboundTeid"/> is non-null, inbound G-PDUs whose TEID differs are dropped (null accepts
        /// any inbound G-PDU TEID). When <paramref name="enableSequence"/> is true, an incrementing Sequence Number (S flag)
        /// is added to each outbound G-PDU.
        /// </summary>
        public GtpUFramingTransport(IDatagramTransport inner, uint teid, uint? expectedInboundTeid, bool enableSequence)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _teid = teid;
            _expectedInboundTeid = expectedInboundTeid;
            _enableSequence = enableSequence;
        }

        /// <inheritdoc/>
        public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => _inner.ConnectAsync(cancellationToken);

        /// <inheritdoc/>
        public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
        {
            ushort? sequence = _enableSequence
                ? unchecked((ushort)Interlocked.Increment(ref _sequenceNumber))
                : (ushort?)null;
            byte[] framed = GtpUHeader.Encode(_teid, datagram.Span, sequence);
            return _inner.SendAsync(framed, cancellationToken);
        }

        /// <inheritdoc/>
        public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            byte[] scratch = _receiveScratch ??= new byte[ushort.MaxValue];
            int n = await _inner.ReceiveAsync(scratch, cancellationToken).ConfigureAwait(false);
            if (n <= 0) return 0;

            if (!GtpUHeader.TryDecode(scratch.AsSpan(0, n), out GtpUHeader header))
                return 0; // runt / wrong version / bad length / truncated extension — drop
            if (!header.IsGPdu)
                return 0; // Echo Request/Response, Error Indication or any non-user message type — drop
            if (_expectedInboundTeid.HasValue && header.Teid != _expectedInboundTeid.Value)
                return 0; // a different tunnel on the same port — drop (this tunnel carries one TEID)
            if (header.PayloadLength <= 0)
                return 0; // header-only G-PDU (nothing to surface)

            int copy = Math.Min(buffer.Length, header.PayloadLength);
            scratch.AsMemory(header.PayloadOffset, copy).CopyTo(buffer);
            return copy;
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
