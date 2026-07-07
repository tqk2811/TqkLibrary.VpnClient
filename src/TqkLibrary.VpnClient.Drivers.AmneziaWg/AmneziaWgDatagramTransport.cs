using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.WireGuard;

namespace TqkLibrary.VpnClient.Drivers.AmneziaWg
{
    /// <summary>
    /// An <see cref="IDatagramTransport"/> decorator that applies AmneziaWG obfuscation over an <b>inner</b> UDP pipe: on
    /// <see cref="SendAsync"/> it obfuscates each outgoing WireGuard datagram (and, exactly once, emits the Jc junk
    /// packets just before the first handshake initiation), and on <see cref="ReceiveAsync"/> it de-obfuscates, silently
    /// dropping junk and looping until a real WireGuard datagram arrives. Boundaries are preserved (one WireGuard message
    /// = one obfuscated datagram = one inner datagram, plus the standalone junk datagrams), so it is a drop-in replacement
    /// for a raw UDP transport under a WireGuard session. <see cref="ConnectAsync"/>/<see cref="DisposeAsync"/> delegate to
    /// the inner pipe (disposed with this transport when <c>ownsInner</c>).
    /// <para>
    /// In the WireGuard driver's socket/loopback wiring the inbound path runs through the receiver the connection wires,
    /// not <see cref="ReceiveAsync"/>; <see cref="AmneziaWgTransportFactory"/> wraps that receiver too. <see cref="ReceiveAsync"/>
    /// is provided for completeness and for direct datagram-transport use (e.g. offline loopback tests).
    /// </para>
    /// </summary>
    public sealed class AmneziaWgDatagramTransport : IDatagramTransport
    {
        readonly IDatagramTransport _inner;
        readonly AmneziaWgObfuscator _obfuscator;
        readonly bool _ownsInner;
        int _junkSent; // 0 until the Jc junk burst has been emitted before the first initiation

        /// <summary>
        /// Wraps <paramref name="inner"/> (the plaintext UDP pipe) with <paramref name="obfuscator"/>. When
        /// <paramref name="ownsInner"/> is true (the default) disposing this transport also disposes the inner pipe.
        /// </summary>
        public AmneziaWgDatagramTransport(IDatagramTransport inner, AmneziaWgObfuscator obfuscator, bool ownsInner = true)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _obfuscator = obfuscator ?? throw new ArgumentNullException(nameof(obfuscator));
            _ownsInner = ownsInner;
        }

        /// <inheritdoc/>
        public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => _inner.ConnectAsync(cancellationToken);

        /// <inheritdoc/>
        public async ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
        {
            // The first handshake initiation is preceded by the Jc random junk packets (each sent as its own datagram).
            if (IsInitiation(datagram.Span) && Interlocked.Exchange(ref _junkSent, 1) == 0)
            {
                IReadOnlyList<byte[]> junk = _obfuscator.GenerateJunkPackets();
                for (int i = 0; i < junk.Count; i++)
                    await _inner.SendAsync(junk[i], cancellationToken).ConfigureAwait(false);
            }

            byte[] wire = _obfuscator.Obfuscate(datagram.Span);
            await _inner.SendAsync(wire, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            // The obfuscated wire is at most the WireGuard datagram plus the S1/S2 prefix; size the temp buffer generously
            // so a real packet always fits (an over-long junk packet is dropped anyway).
            int tempSize = Math.Max(buffer.Length, 65535) + Math.Max(_obfuscator.Parameters.S1, _obfuscator.Parameters.S2) + 4;
            byte[] temp = new byte[tempSize];
            while (true)
            {
                int read = await _inner.ReceiveAsync(temp, cancellationToken).ConfigureAwait(false);
                if (read <= 0) continue; // a 0-length datagram is not a close on UDP
                if (!_obfuscator.TryDeobfuscate(temp.AsSpan(0, read), out byte[] wg))
                    continue; // junk ⇒ drop, keep waiting for a real datagram
                int n = Math.Min(wg.Length, buffer.Length);
                wg.AsSpan(0, n).CopyTo(buffer.Span);
                return n;
            }
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            if (_ownsInner)
                await _inner.DisposeAsync().ConfigureAwait(false);
        }

        /// <summary>True when the datagram is a WireGuard handshake initiation (type 1, uint32 little-endian at offset 0).</summary>
        static bool IsInitiation(ReadOnlySpan<byte> datagram) =>
            datagram.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(datagram) == WireGuardConstants.MessageTypeInitiation;
    }
}
