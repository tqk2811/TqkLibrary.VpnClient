using System;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Fou
{
    /// <summary>
    /// An <see cref="IDatagramTransport"/> decorator that adds the GUE variant-0 header (draft-ietf-intarea-gue) around an
    /// inner UDP pipe, so the reused inner data-plane channels (<c>GreTunnelChannel</c> / <c>RawIpPassthroughChannel</c>)
    /// need no GUE awareness. Outbound: prepend a 4-byte GUE header stamped with the configured inner protocol number.
    /// Inbound: strip and validate the header via <see cref="GueHeader.TryDecode"/> and surface only the payload — a
    /// datagram that is not a valid variant-0 data packet (bad version, control message, truncated) or whose protocol does
    /// not match the configured inner protocol is <b>dropped</b> by returning 0 length, which the channel's receive loop
    /// treats as "nothing to deliver". FOU (headerless) mode does not use this decorator.
    /// </summary>
    internal sealed class GueFramingTransport : IDatagramTransport
    {
        readonly IDatagramTransport _inner;
        readonly byte _protocol;
        byte[]? _receiveScratch;

        /// <summary>Wraps <paramref name="inner"/>, stamping/expecting GUE payloads for IP protocol <paramref name="protocol"/>.</summary>
        public GueFramingTransport(IDatagramTransport inner, byte protocol)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _protocol = protocol;
        }

        /// <inheritdoc/>
        public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => _inner.ConnectAsync(cancellationToken);

        /// <inheritdoc/>
        public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
        {
            byte[] framed = GueHeader.Encode(_protocol, datagram.Span);
            return _inner.SendAsync(framed, cancellationToken);
        }

        /// <inheritdoc/>
        public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            byte[] scratch = _receiveScratch ??= new byte[ushort.MaxValue];
            int n = await _inner.ReceiveAsync(scratch, cancellationToken).ConfigureAwait(false);
            if (n <= 0) return 0;

            if (!GueHeader.TryDecode(scratch.AsSpan(0, n), out byte protocol, out int payloadOffset))
                return 0; // malformed / wrong version / control message — drop
            if (protocol != _protocol)
                return 0; // a different inner protocol on the same port — drop (this tunnel carries one inner proto)

            int payloadLength = n - payloadOffset;
            if (payloadLength <= 0) return 0; // header-only (e.g. keepalive) — nothing to surface

            int copy = Math.Min(buffer.Length, payloadLength);
            scratch.AsMemory(payloadOffset, copy).CopyTo(buffer);
            return copy;
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
