using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// An <see cref="IPacketChannel"/> facade that decouples an inner channel's inbound delivery from its consumer with
    /// a bounded queue + a single read-loop (design 09 §"Hiệu năng": <c>System.Threading.Channels</c>, "1 read-loop per
    /// VirtualHost"). The inner channel (typically a <see cref="VirtualHost"/>) raises <see cref="IPacketChannel.InboundIpPacket"/>
    /// synchronously from the switch's deliver path; that call would otherwise run the bound IP stack inline, so a slow
    /// stack would stall the whole in-memory fabric. This wrapper instead copies each inbound packet into a bounded
    /// channel and re-raises it from its own pump task, applying backpressure (the channel's
    /// <see cref="BoundedChannelFullMode"/> decides whether a producer waits or the oldest/newest packet is dropped when
    /// the consumer falls behind).
    /// <para>
    /// Egress (<see cref="WriteIpPacketAsync"/>) passes straight through to the inner channel. Link metadata
    /// (<see cref="Mtu"/> etc.) mirrors the inner channel. Disposing this disposes the inner channel and stops the pump.
    /// </para>
    /// </summary>
    public sealed class BackpressuredPacketChannel : IPacketChannel
    {
        readonly IPacketChannel _inner;
        readonly Channel<byte[]> _queue;
        readonly CancellationTokenSource _pumpCts = new CancellationTokenSource();
        readonly Task _pumpTask;
        readonly Action<ReadOnlyMemory<byte>> _onInboundInner;
        int _disposed;

        /// <summary>
        /// Wraps <paramref name="inner"/> with a bounded inbound queue of <paramref name="capacity"/> packets, dropping
        /// per <paramref name="fullMode"/> when the consumer cannot keep up.
        /// </summary>
        public BackpressuredPacketChannel(IPacketChannel inner, int capacity = 256, BoundedChannelFullMode fullMode = BoundedChannelFullMode.DropOldest)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            if (capacity < 1)
                throw new ArgumentOutOfRangeException(nameof(capacity), "Capacity must be at least 1.");

            _queue = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(capacity)
            {
                SingleReader = true,    // exactly one pump drains the queue
                SingleWriter = false,   // the inner channel may raise from any thread
                FullMode = fullMode,
            });

            // A cached delegate instance so the -= in DisposeAsync actually detaches.
            _onInboundInner = OnInboundInner;
            _inner.InboundIpPacket += _onInboundInner;
            _pumpTask = Task.Run(PumpAsync);
        }

        /// <inheritdoc/>
        public LinkMedium Medium => _inner.Medium;

        /// <inheritdoc/>
        public int Mtu => _inner.Mtu;

        /// <inheritdoc/>
        public int MaxHeaderLength => _inner.MaxHeaderLength;

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution => _inner.RequiresLinkAddressResolution;

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

        /// <inheritdoc/>
        public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            => _inner.WriteIpPacketAsync(ipPacket, cancellationToken);

        /// <summary>Inner channel → bounded queue. Copies the buffer (it is only valid in-handler) then enqueues.</summary>
        void OnInboundInner(ReadOnlyMemory<byte> packet)
        {
            if (Volatile.Read(ref _disposed) != 0)
                return;
            // TryWrite never blocks: with DropOldest/DropNewest it always succeeds; with Wait it returns false when full
            // (we don't await here because we're on the synchronous switch path — a Wait-mode overflow drops instead).
            _queue.Writer.TryWrite(packet.ToArray());
        }

        /// <summary>The single read-loop: drains the queue and re-raises packets to the bound stack off the switch path.</summary>
        async Task PumpAsync()
        {
            ChannelReader<byte[]> reader = _queue.Reader;
            try
            {
                while (await reader.WaitToReadAsync(_pumpCts.Token).ConfigureAwait(false))
                {
                    while (reader.TryRead(out byte[]? packet))
                    {
                        try { InboundIpPacket?.Invoke(packet); }
                        catch { /* a faulty subscriber must not kill the pump */ }
                    }
                }
            }
            catch (OperationCanceledException) { /* disposed */ }
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;

            _inner.InboundIpPacket -= _onInboundInner;
            _queue.Writer.TryComplete();
#if NET8_0_OR_GREATER
            await _pumpCts.CancelAsync().ConfigureAwait(false);
#else
            _pumpCts.Cancel();
#endif
            try { await _pumpTask.ConfigureAwait(false); } catch { /* pump cancelled */ }
            _pumpCts.Dispose();
            InboundIpPacket = null;
            await _inner.DisposeAsync().ConfigureAwait(false);
        }
    }
}
