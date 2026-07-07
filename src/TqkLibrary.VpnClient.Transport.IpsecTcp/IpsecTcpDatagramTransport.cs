using System.IO;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Transport.Tcp;
using TqkLibrary.VpnClient.Transport.Tls;

namespace TqkLibrary.VpnClient.Transport.IpsecTcp
{
    /// <summary>
    /// TCP encapsulation of IKE and ESP (RFC 8229): an <see cref="IDatagramTransport"/> (preserved datagram boundaries)
    /// layered over an <see cref="IByteStreamTransport"/> (a raw byte stream). It lets IKE/ESP traverse firewalls that
    /// block UDP/500+4500 by re-framing each datagram with a 16-bit length prefix (§2) and, when it is the initiator,
    /// emitting the <c>"IKETCP"</c> stream prefix once after connecting (§3). Wrapping a TLS byte stream instead of a
    /// plain TCP one yields the §5 "looks like HTTPS" variant with no extra code here.
    /// <para>
    /// This adapter is purely a framing decorator. The IKE-vs-ESP demultiplexing (RFC 3948 non-ESP marker) is handled
    /// by the IPsec NAT-T layer (<c>Ipsec/Nat</c>), so every datagram passing through here is opaque.
    /// </para>
    /// </summary>
    public sealed class IpsecTcpDatagramTransport : IDatagramTransport
    {
        // One-time static copy so ConnectAsync can WriteAsync the prefix without allocating per instance.
        static readonly byte[] _streamPrefixBytes = Rfc8229Framing.StreamPrefix.ToArray();

        readonly IByteStreamTransport _inner;
        readonly bool _sendStreamPrefix;
        readonly Rfc8229Reassembler _reassembler;
        readonly byte[] _readBuffer = new byte[8192];

        /// <summary>
        /// Wraps an existing <paramref name="inner"/> byte stream (injectable for TCP, TLS, or an in-memory loopback).
        /// <paramref name="sendStreamPrefix"/> selects the RFC 8229 role: the initiator (<c>true</c>, the default) sends
        /// the <c>"IKETCP"</c> prefix and expects none inbound; a responder (<c>false</c>) sends none and expects the
        /// initiator's prefix inbound. Ownership of <paramref name="inner"/> transfers here — <see cref="DisposeAsync"/>
        /// disposes it.
        /// </summary>
        public IpsecTcpDatagramTransport(IByteStreamTransport inner, bool sendStreamPrefix = true)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _sendStreamPrefix = sendStreamPrefix;
            // RFC 8229 §3 role asymmetry: the party that sends the prefix does not expect one inbound, and vice versa.
            _reassembler = new Rfc8229Reassembler(expectStreamPrefix: !sendStreamPrefix);
        }

        /// <summary>
        /// Convenience initiator constructor that builds its own inner byte stream to <paramref name="host"/>:
        /// <paramref name="port"/>: a <see cref="TlsByteStream"/> when <paramref name="useTls"/> is <c>true</c> (§5
        /// TLS variant), otherwise a plain <see cref="TcpByteStream"/>. Always sends the stream prefix (initiator role).
        /// </summary>
        public IpsecTcpDatagramTransport(string host, int port, bool useTls = false)
            : this(useTls ? new TlsByteStream(host, port) : (IByteStreamTransport)new TcpByteStream(host, port), sendStreamPrefix: true)
        {
        }

        /// <inheritdoc/>
        public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
        {
            await _inner.ConnectAsync(cancellationToken).ConfigureAwait(false);
            // §3: the initiator sends the six-byte "IKETCP" stream prefix exactly once, before any message.
            if (_sendStreamPrefix)
                await _inner.WriteAsync(_streamPrefixBytes, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
        {
            byte[] frame = Rfc8229Framing.Frame(datagram.Span);
            await _inner.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (true)
            {
                if (_reassembler.TryReadMessage(out byte[] message))
                {
                    if (message.Length > buffer.Length)
                        throw new ArgumentException(
                            $"The receive buffer ({buffer.Length} bytes) is smaller than the {message.Length}-byte datagram.", nameof(buffer));
                    message.AsSpan().CopyTo(buffer.Span);
                    return message.Length;
                }

                int read = await _inner.ReadAsync(_readBuffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    // The byte stream closed. Mid-frame is a truncated message; at a clean frame boundary it is EOF.
                    if (_reassembler.HasBufferedData)
                        throw new EndOfStreamException("The inner byte stream closed in the middle of an RFC 8229 frame.");
                    throw new EndOfStreamException("The inner byte stream closed.");
                }
                _reassembler.Append(_readBuffer.AsSpan(0, read));
            }
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
