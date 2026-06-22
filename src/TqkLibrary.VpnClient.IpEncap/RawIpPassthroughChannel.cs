using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.IpEncap
{
    /// <summary>
    /// A header-less IP-in-IP L3 data plane serving BOTH IPIP (RFC 2003, IP proto 4 — IPv4-in-IPv4) and SIT/6in4
    /// (RFC 4213, IP proto 41 — IPv6-in-IPv4): there is no encapsulation header, so the inner IP packet IS the raw-IP
    /// payload. Outbound sends the inner packet verbatim as the datagram; inbound raises the received payload verbatim on
    /// <see cref="InboundIpPacket"/>. The proto number (4 vs 41) is fixed by the caller when it creates the
    /// <see cref="IDatagramTransport"/>; this channel is family-agnostic and carries whatever the IP version nibble says,
    /// exactly like a PPP IP channel. UNENCRYPTED — use only on a trusted path or under IPsec.
    /// </summary>
    public sealed class RawIpPassthroughChannel : IPacketChannel
    {
        readonly IDatagramTransport _transport;
        readonly ILogger _logger;

        readonly object _gate = new object();
        CancellationTokenSource? _loopCts;
        Task? _loopTask;
        bool _disposed;

        /// <summary>Creates a passthrough channel over <paramref name="transport"/> (a connected raw-IP proto-4 or proto-41 pipe).</summary>
        /// <param name="mtu">Inner-packet MTU advertised to the stack (outer-IP overhead already deducted by the caller).</param>
        public RawIpPassthroughChannel(IDatagramTransport transport, int mtu = 1480, ILogger? logger = null)
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            Mtu = mtu;
            _logger = logger ?? NullLogger.Instance;
        }

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ip;

        /// <inheritdoc/>
        public int Mtu { get; }

        /// <inheritdoc/>
        public int MaxHeaderLength => 0;

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution => false;

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

        /// <summary>Starts the inbound receive loop (idempotent).</summary>
        public void Start()
        {
            lock (_gate)
            {
                if (_disposed) throw new ObjectDisposedException(nameof(RawIpPassthroughChannel));
                if (_loopTask != null) return;
                _loopCts = new CancellationTokenSource();
                _loopTask = Task.Run(() => ReceiveLoopAsync(_loopCts.Token));
            }
        }

        /// <inheritdoc/>
        public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            // No header: the inner IP packet is the raw-IP payload verbatim (RFC 2003 / RFC 4213).
            => _transport.SendAsync(ipPacket, cancellationToken);

        async Task ReceiveLoopAsync(CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[ushort.MaxValue];
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    int n = await _transport.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (cancellationToken.IsCancellationRequested) break;
                    if (n <= 0) continue;

                    // The payload IS the inner IP packet; copy out (the buffer is reused on the next receive).
                    InboundIpPacket?.Invoke(buffer.AsSpan(0, n).ToArray());
                }
            }
            catch (OperationCanceledException) { }
            catch
            {
                // The transport was disposed on teardown, or a receive error occurred. A real link drop surfaces to the
                // supervisor above via the absence of inbound packets.
            }
        }

        /// <summary>Stops the receive loop and disposes the underlying transport.</summary>
        public async ValueTask DisposeAsync()
        {
            CancellationTokenSource? cts;
            Task? loop;
            lock (_gate)
            {
                if (_disposed) return;
                _disposed = true;
                cts = _loopCts;
                loop = _loopTask;
                _loopCts = null;
                _loopTask = null;
            }

            cts?.Cancel();
            await _transport.DisposeAsync().ConfigureAwait(false);
            if (loop != null)
            {
                try { await loop.ConfigureAwait(false); }
                catch { /* loop teardown errors are benign */ }
            }
            cts?.Dispose();
        }
    }
}
