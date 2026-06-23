using System.Collections.Generic;
using System.Threading;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.SoftEther.DataChannel.Enums;

namespace TqkLibrary.VpnClient.SoftEther.DataChannel
{
    /// <summary>
    /// Aggregates the 1–32 parallel TCP/TLS connections of one logical SoftEther session into a single data path
    /// ("1 session owning N sockets"). After the primary login and each <c>additional_connect</c>, every connection is
    /// added here tagged with its <see cref="SoftEtherConnectionDirection"/>. Egress data blocks are spread round-robin
    /// across the send-capable connections (so throughput pools); ingress runs one read loop per receive-capable
    /// connection — each decodes self-contained <see cref="SoftEtherDataBlockReader">blocks</see> independently and
    /// raises <see cref="InboundFrame"/> per frame. Because SoftEther frames are self-contained (no cross-connection
    /// sequencing at the block layer), reassembly is simply the union of all inbound frames; ordering within one
    /// connection is preserved, and the IP/TCP layers above tolerate the modest reorder between connections (mirroring
    /// the real client's "1 session, N connections" model).
    /// <para>
    /// In <c>half_connection</c> sessions some connections are <see cref="SoftEtherConnectionDirection.Send"/> (egress
    /// only) and the rest <see cref="SoftEtherConnectionDirection.Receive"/> (ingress only); a degenerate single
    /// connection (<see cref="SoftEtherConnectionDirection.Both"/>) behaves exactly like the old one-socket data path.
    /// The first send-/receive-loop fault (peer close or read error) is reported once via the <c>linkLost</c> callback.
    /// This type holds the sockets and the read loops but no L2 logic — it feeds a <see cref="SoftEtherEthernetChannel"/>.
    /// </para>
    /// </summary>
    public sealed class SoftEtherMultiConnectionMux : IAsyncDisposable
    {
        readonly IByteStreamTransport[] _connections;
        readonly SoftEtherConnectionDirection[] _directions;
        readonly int[] _sendIndices;          // indices of connections eligible to send
        readonly Action<string> _linkLost;
        readonly CancellationTokenSource _cts = new();

        readonly List<Task> _receiveLoops = new();
        Action<ReadOnlyMemory<byte>>? _inboundFrame;
        int _sendCursor = -1;
        int _linkLostRaised;                  // 0 → not yet; one-shot guard so a fault is reported once

        /// <summary>
        /// Wires the mux over <paramref name="connections"/> (already connected + handshaken: the primary login and each
        /// <c>additional_connect</c>), with the matching per-connection <paramref name="directions"/>.
        /// <paramref name="linkLost"/> is invoked once when any send/receive connection faults or the peer closes it.
        /// </summary>
        public SoftEtherMultiConnectionMux(
            IReadOnlyList<IByteStreamTransport> connections,
            IReadOnlyList<SoftEtherConnectionDirection> directions,
            Action<string> linkLost)
        {
            if (connections is null) throw new ArgumentNullException(nameof(connections));
            if (directions is null) throw new ArgumentNullException(nameof(directions));
            if (connections.Count == 0) throw new ArgumentException("At least one connection is required.", nameof(connections));
            if (connections.Count != directions.Count)
                throw new ArgumentException("connections and directions must have the same length.", nameof(directions));
            _linkLost = linkLost ?? throw new ArgumentNullException(nameof(linkLost));

            _connections = new IByteStreamTransport[connections.Count];
            _directions = new SoftEtherConnectionDirection[connections.Count];
            var sendList = new List<int>(connections.Count);
            for (int i = 0; i < connections.Count; i++)
            {
                _connections[i] = connections[i] ?? throw new ArgumentException("A connection is null.", nameof(connections));
                _directions[i] = directions[i];
                if (directions[i] != SoftEtherConnectionDirection.Receive)
                    sendList.Add(i);
            }
            if (sendList.Count == 0)
                throw new ArgumentException("At least one connection must be able to send (Both or Send).", nameof(directions));
            _sendIndices = sendList.ToArray();
        }

        /// <summary>The number of TCP/TLS connections backing this session.</summary>
        public int ConnectionCount => _connections.Length;

        /// <summary>Raised once per inbound (non-keep-alive) frame decoded on any receive-capable connection.</summary>
        public event Action<ReadOnlyMemory<byte>>? InboundFrame
        {
            add => _inboundFrame += value;
            remove => _inboundFrame -= value;
        }

        /// <summary>Starts one decode loop per receive-capable connection. Call once after construction.</summary>
        public void StartReceiveLoops()
        {
            CancellationToken token = _cts.Token;
            for (int i = 0; i < _connections.Length; i++)
            {
                if (_directions[i] == SoftEtherConnectionDirection.Send) continue;   // send-only: no read loop
                IByteStreamTransport connection = _connections[i];
                _receiveLoops.Add(Task.Run(() => ReceiveLoopAsync(connection, token)));
            }
        }

        /// <summary>
        /// Writes one already-encoded data block to the next send-capable connection (round-robin), pooling throughput
        /// across the parallel sockets. With a single connection this is just that one socket.
        /// </summary>
        public ValueTask SendBlockAsync(ReadOnlyMemory<byte> block, CancellationToken cancellationToken = default)
        {
            // Round-robin pick among send-eligible connections; one socket ⇒ always index 0.
            int next = _sendIndices.Length == 1 ? 0 : (int)((uint)Interlocked.Increment(ref _sendCursor) % (uint)_sendIndices.Length);
            return _connections[_sendIndices[next]].WriteAsync(block, cancellationToken);
        }

        async Task ReceiveLoopAsync(IByteStreamTransport connection, CancellationToken cancellationToken)
        {
            var reader = new SoftEtherDataBlockReader(connection);
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    IReadOnlyList<byte[]> frames = await reader.ReadBlockAsync(cancellationToken).ConfigureAwait(false);
                    if (frames.Count == 0)
                    {
                        RaiseLinkLost("SoftEther server closed a data connection.");
                        return;
                    }
                    Action<ReadOnlyMemory<byte>>? sink = _inboundFrame;
                    if (sink is null) continue;
                    for (int i = 0; i < frames.Count; i++)
                        sink(frames[i]);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { /* teardown */ }
            catch (Exception ex)
            {
                RaiseLinkLost($"SoftEther data connection faulted while reading: {ex.GetType().Name}: {ex.Message}");
            }
        }

        void RaiseLinkLost(string reason)
        {
            if (Interlocked.Exchange(ref _linkLostRaised, 1) == 0)
                _linkLost(reason);
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            try { _cts.Cancel(); } catch { }
            for (int i = 0; i < _receiveLoops.Count; i++)
            {
                try { await _receiveLoops[i].ConfigureAwait(false); } catch { }
            }
            for (int i = 0; i < _connections.Length; i++)
            {
                try { await _connections[i].DisposeAsync().ConfigureAwait(false); } catch { }
            }
            _cts.Dispose();
        }
    }
}
