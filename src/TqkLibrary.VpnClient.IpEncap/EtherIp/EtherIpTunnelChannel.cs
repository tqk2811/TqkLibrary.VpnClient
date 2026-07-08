using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.IpEncap.EtherIp
{
    /// <summary>
    /// The EtherIP (RFC 3378) L2 data plane: an <see cref="IEthernetChannel"/> over an <see cref="IDatagramTransport"/>
    /// raw-IP proto-97 pipe, bridging Ethernet over IP. Outbound Ethernet frames are wrapped in the fixed 2-byte EtherIP
    /// header (<see cref="EtherIpCodec.Encapsulate"/>) and sent as the datagram; inbound datagrams are decapsulated and the
    /// recovered frame is raised on <see cref="InboundFrame"/>, plugging straight into the userspace Ethernet fabric
    /// (ARP + the VirtualHost bridge). Because the payload is a full Ethernet frame, <see cref="MaxHeaderLength"/> is 14 and
    /// <see cref="RequiresLinkAddressResolution"/> is true.
    /// <para>
    /// Structurally this mirrors <c>GreTunnelChannel</c>: a dedicated receive loop (started by <see cref="Start"/>), an
    /// identity guard that drops a stale loop after teardown, and disposing the transport to unblock a pending receive.
    /// UNENCRYPTED — use only on a trusted path or under IPsec. (The outer-IP proto-97 send/receive is a live follow-up;
    /// this channel drives the EtherIP header + Ethernet-frame passthrough over whatever <see cref="IDatagramTransport"/>
    /// the caller supplies.)
    /// </para>
    /// </summary>
    public sealed class EtherIpTunnelChannel : IEthernetChannel
    {
        readonly IDatagramTransport _transport;
        readonly EtherIpTunnelOptions _options;
        readonly ILogger _logger;
        readonly byte[] _linkAddress;

        readonly object _gate = new object();
        CancellationTokenSource? _loopCts;
        Task? _loopTask;
        bool _disposed;

        /// <summary>Creates an EtherIP channel over <paramref name="transport"/> (a connected raw-IP proto-97 pipe).</summary>
        public EtherIpTunnelChannel(IDatagramTransport transport, EtherIpTunnelOptions? options = null, ILogger? logger = null)
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _options = options ?? new EtherIpTunnelOptions();
            _linkAddress = _options.LinkAddress.ToArray();
            _logger = logger ?? NullLogger.Instance;
        }

        /// <inheritdoc/>
        public ReadOnlyMemory<byte> LinkAddress => _linkAddress;

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ethernet;

        /// <inheritdoc/>
        public int Mtu => _options.Mtu;

        /// <inheritdoc/>
        public int MaxHeaderLength => EtherIpCodec.EthernetHeaderLength; // 14 — the Ethernet II header the fabric prepends

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution => true;

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundFrame;

        /// <summary>Starts the inbound EtherIP receive loop (idempotent).</summary>
        public void Start()
        {
            lock (_gate)
            {
                if (_disposed) throw new ObjectDisposedException(nameof(EtherIpTunnelChannel));
                if (_loopTask != null) return;
                _loopCts = new CancellationTokenSource();
                _loopTask = Task.Run(() => ReceiveLoopAsync(_loopCts.Token));
            }
        }

        /// <inheritdoc/>
        // Non-async so the frame Span never enters an async frame: encapsulate first, then hand the datagram to the transport.
        public ValueTask WriteFrameAsync(ReadOnlyMemory<byte> ethernetFrame, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (ethernetFrame.Length < EtherIpCodec.EthernetHeaderLength) return default; // too short to be an Ethernet frame — drop
            byte[] datagram = EtherIpCodec.Encapsulate(ethernetFrame.Span);
            return _transport.SendAsync(datagram, cancellationToken);
        }

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

                    if (!EtherIpCodec.TryDecapsulate(buffer.AsSpan(0, n), out byte[] frame))
                    {
                        _logger.LogTrace("EtherIP: dropped a malformed packet ({Length} bytes).", n);
                        continue;
                    }

                    InboundFrame?.Invoke(frame);
                }
            }
            catch (OperationCanceledException) { }
            catch
            {
                // The transport was disposed on teardown, or a receive error occurred. A real link drop surfaces to the
                // supervisor above via the absence of inbound frames.
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
            InboundFrame = null;
        }
    }
}
