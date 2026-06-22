using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.IpEncap.Gre
{
    /// <summary>
    /// The standard GRE (RFC 2784/2890) L3 data plane: an <see cref="IPacketChannel"/> over an
    /// <see cref="IDatagramTransport"/> raw-IP proto-47 pipe. Outbound IP packets are wrapped in a GRE header whose
    /// Protocol Type is chosen from the inner IP version (0x0800 IPv4 / 0x86DD IPv6), optionally carrying a Key /
    /// Sequence Number / Checksum per <see cref="GreTunnelOptions"/>; inbound GRE packets are unwrapped and the inner IP
    /// packet is raised on <see cref="InboundIpPacket"/>. A dedicated receive loop (started by <see cref="Start"/>)
    /// mirrors the PPTP-GRE / native-ESP loop pattern: an identity guard drops a stale loop after teardown, and disposing
    /// the transport unblocks a pending receive. UNENCRYPTED — use only on a trusted path or under IPsec.
    /// </summary>
    public sealed class GreTunnelChannel : IPacketChannel
    {
        readonly IDatagramTransport _transport;
        readonly GreTunnelOptions _options;
        readonly ILogger _logger;

        readonly object _gate = new object();
        CancellationTokenSource? _loopCts;
        Task? _loopTask;
        bool _disposed;
        uint _nextSeq; // next sequence number to send (increments per packet when EmitSequenceNumber)

        /// <summary>Creates a GRE channel over <paramref name="transport"/> (a connected raw-IP proto-47 pipe).</summary>
        public GreTunnelChannel(IDatagramTransport transport, GreTunnelOptions? options = null, ILogger? logger = null)
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _options = options ?? new GreTunnelOptions();
            _logger = logger ?? NullLogger.Instance;
        }

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ip;

        /// <inheritdoc/>
        public int Mtu => _options.Mtu;

        /// <inheritdoc/>
        public int MaxHeaderLength => 0;

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution => false;

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

        /// <summary>Starts the inbound GRE receive loop (idempotent).</summary>
        public void Start()
        {
            lock (_gate)
            {
                if (_disposed) throw new ObjectDisposedException(nameof(GreTunnelChannel));
                if (_loopTask != null) return;
                _loopCts = new CancellationTokenSource();
                _loopTask = Task.Run(() => ReceiveLoopAsync(_loopCts.Token));
            }
        }

        /// <inheritdoc/>
        public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
        {
            byte[]? datagram = BuildGre(ipPacket.Span);
            if (datagram is null) return default; // not a recognisable IPv4/IPv6 packet — drop
            return _transport.SendAsync(datagram, cancellationToken);
        }

        // Non-async so the inner-packet Span never enters an async frame. Returns null when the first nibble is neither
        // 4 nor 6, so a malformed buffer is dropped rather than mislabelled.
        byte[]? BuildGre(ReadOnlySpan<byte> ipPacket)
        {
            if (ipPacket.Length == 0) return null;
            byte version = (byte)(ipPacket[0] >> 4);
            ushort protocolType = version switch
            {
                4 => GreCodec.ProtocolTypeIpv4,
                6 => GreCodec.ProtocolTypeIpv6,
                _ => 0,
            };
            if (protocolType == 0) return null;

            uint? seq = null;
            if (_options.EmitSequenceNumber)
            {
                lock (_gate) seq = _nextSeq++;
            }

            var packet = new GrePacket
            {
                ProtocolType = protocolType,
                Key = _options.Key,
                SequenceNumber = seq,
                IncludeChecksum = _options.EmitChecksum,
                Payload = ipPacket.ToArray(),
            };
            return GreCodec.Encode(packet);
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

                    if (!GreCodec.TryDecode(buffer.AsSpan(0, n), out GrePacket? packet) || packet is null)
                    {
                        _logger.LogTrace("GRE: dropped a malformed packet ({Length} bytes).", n);
                        continue;
                    }
                    if (packet.ProtocolType != GreCodec.ProtocolTypeIpv4 && packet.ProtocolType != GreCodec.ProtocolTypeIpv6)
                    {
                        _logger.LogTrace("GRE: dropped a packet with protocol type {Type:X4}.", packet.ProtocolType);
                        continue;
                    }
                    if (packet.Payload.Length == 0) continue; // keepalive / empty — nothing to surface

                    InboundIpPacket?.Invoke(packet.Payload);
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
