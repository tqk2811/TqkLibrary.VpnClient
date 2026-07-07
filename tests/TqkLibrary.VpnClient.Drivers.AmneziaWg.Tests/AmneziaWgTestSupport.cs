using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.AmneziaWg.Interfaces;
using TqkLibrary.VpnClient.Drivers.AmneziaWg.Models;

namespace TqkLibrary.VpnClient.Drivers.AmneziaWg.Tests
{
    /// <summary>Shared fixtures for the AmneziaWG offline tests: sample parameters, a WireGuard datagram builder, a
    /// deterministic random source, and an in-memory datagram pipe.</summary>
    static class AmneziaWgTestSupport
    {
        /// <summary>A valid parameter set (H1..H4 distinct and &gt; 4; small padding/junk) shared across the tests.</summary>
        public static AmneziaWgParameters SampleParameters() => new AmneziaWgParameters
        {
            Jc = 3,
            Jmin = 10,
            Jmax = 20,
            S1 = 5,
            S2 = 7,
            H1 = 0x10000001u,
            H2 = 0x10000002u,
            H3 = 0x10000003u,
            H4 = 0x10000004u,
        };

        /// <summary>Builds a plausible WireGuard datagram: type byte at offset 0, reserved 1..3 = 0, deterministic body.</summary>
        public static byte[] WgDatagram(byte type, int length)
        {
            byte[] d = new byte[length];
            d[0] = type; // bytes 1..3 stay 0 (WireGuard reserved)
            for (int i = 4; i < length; i++) d[i] = (byte)((i * 7 + 3) & 0xFF);
            return d;
        }

        public static uint ReadU32(ReadOnlySpan<byte> span, int offset) =>
            BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(offset));
    }

    /// <summary>A deterministic <see cref="IAmneziaWgRandom"/>: junk bytes are a fixed fill; sizes come from a picker.</summary>
    sealed class DeterministicRandom : IAmneziaWgRandom
    {
        readonly byte _fill;
        readonly Func<int, int, int>? _sizePicker;

        public DeterministicRandom(byte fill = 0x00, Func<int, int, int>? sizePicker = null)
        {
            _fill = fill;
            _sizePicker = sizePicker;
        }

        public byte[] NextBytes(int count)
        {
            byte[] b = new byte[count];
            for (int i = 0; i < count; i++) b[i] = _fill;
            return b;
        }

        public int NextInt(int minInclusive, int maxInclusive) => _sizePicker?.Invoke(minInclusive, maxInclusive) ?? minInclusive;
    }

    /// <summary>An in-memory <see cref="IDatagramTransport"/>: records every send, optionally forwards to a wired peer,
    /// and yields queued inbound datagrams from <see cref="ReceiveAsync"/>.</summary>
    sealed class InMemoryDatagram : IDatagramTransport
    {
        readonly Channel<byte[]> _inbox = Channel.CreateUnbounded<byte[]>();
        Action<ReadOnlyMemory<byte>>? _sink;

        /// <summary>Every datagram passed to <see cref="SendAsync"/>, in order (for asserting obfuscation/junk bursts).</summary>
        public List<byte[]> Sent { get; } = new List<byte[]>();

        /// <summary>Wires sends from this transport to <paramref name="peer"/>'s inbound queue (bidirectional loopback).</summary>
        public void ConnectTo(InMemoryDatagram peer) => _sink = peer.Deliver;

        /// <summary>Pushes a datagram onto this transport's inbound queue.</summary>
        public void Deliver(ReadOnlyMemory<byte> datagram) => _inbox.Writer.TryWrite(datagram.ToArray());

        public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

        public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
        {
            Sent.Add(datagram.ToArray());
            _sink?.Invoke(datagram);
            return default;
        }

        public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            byte[] d = await _inbox.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            int n = Math.Min(d.Length, buffer.Length);
            d.AsSpan(0, n).CopyTo(buffer.Span);
            return n;
        }

        public ValueTask DisposeAsync()
        {
            _inbox.Writer.TryComplete();
            return default;
        }
    }
}
