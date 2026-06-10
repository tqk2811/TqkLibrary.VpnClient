using System.Diagnostics;

namespace TqkLibrary.Vpn.IpStack
{
    /// <summary>
    /// Reassembles inbound fragmented IPv4 datagrams (RFC 791 §3.2). Whole (non-fragmented) packets pass through
    /// unchanged; fragments are buffered per (source, destination, protocol, identification) until the datagram is
    /// complete or a timeout elapses, then emitted as a single packet with the fragmentation fields cleared.
    /// Incomplete datagrams are discarded after <see cref="Ipv4ReassemblyOptions.Timeout"/>, and the oldest is
    /// evicted once <see cref="Ipv4ReassemblyOptions.MaxConcurrent"/> is exceeded (DoS protection). Thread-safe.
    /// </summary>
    public sealed class Ipv4Reassembler
    {
        readonly Ipv4ReassemblyOptions _options;
        readonly long _timeoutTicks;
        readonly Dictionary<Key, Partial> _pending = new Dictionary<Key, Partial>();
        readonly object _gate = new object();

        /// <summary>Creates a reassembler with default options.</summary>
        public Ipv4Reassembler() : this(Ipv4ReassemblyOptions.Default) { }

        /// <summary>Creates a reassembler with the given options.</summary>
        public Ipv4Reassembler(Ipv4ReassemblyOptions options)
        {
            _options = options ?? Ipv4ReassemblyOptions.Default;
            _timeoutTicks = (long)(_options.Timeout.TotalSeconds * Stopwatch.Frequency);
        }

        /// <summary>Number of in-progress (incomplete) datagrams currently buffered.</summary>
        public int PendingCount { get { lock (_gate) return _pending.Count; } }

        /// <summary>
        /// Offers an inbound IPv4 packet. A non-fragmented packet is returned unchanged. A fragment is buffered and
        /// <c>null</c> is returned until its datagram is complete, at which point the fully reassembled packet is
        /// returned. Malformed or over-limit fragments are dropped (<c>null</c>).
        /// </summary>
        public ReadOnlyMemory<byte>? Offer(ReadOnlyMemory<byte> ipPacket)
        {
            ReadOnlySpan<byte> span = ipPacket.Span;
            if (span.Length < 20) return ipPacket; // too short to be a fragment; let the caller's guards reject it

            bool moreFragments = Ipv4.MoreFragments(span);
            int fragmentOffset = Ipv4.FragmentOffset(span);
            if (!moreFragments && fragmentOffset == 0) return ipPacket; // whole datagram, not a fragment

            int headerLength = Ipv4.HeaderLength(span);
            int totalLength = Ipv4.TotalLength(span);
            if (headerLength < 20 || totalLength < headerLength || totalLength > span.Length) return null; // malformed

            int payloadLength = totalLength - headerLength;
            int start = fragmentOffset;
            int end = fragmentOffset + payloadLength;
            if (headerLength + end > _options.MaxDatagramSize) return null; // would exceed the IP datagram cap

            long now = Stopwatch.GetTimestamp();
            Key key = Key.From(span);

            lock (_gate)
            {
                Expire(now);

                if (!_pending.TryGetValue(key, out Partial? part))
                {
                    if (_pending.Count >= _options.MaxConcurrent) EvictOldest();
                    part = new Partial(now + _timeoutTicks, now);
                    _pending[key] = part;
                }

                part.Add(start, end, span.Slice(headerLength, payloadLength));
                if (!moreFragments) part.TotalLength = end;

                if (!part.IsComplete) return null;

                _pending.Remove(key);
                return Ipv4.Build(Ipv4.Source(span), Ipv4.Destination(span), Ipv4.Protocol(span),
                    new ReadOnlySpan<byte>(part.Buffer, 0, part.TotalLength), Ipv4.Identification(span));
            }
        }

        void Expire(long now)
        {
            if (_pending.Count == 0) return;
            List<Key>? dead = null;
            foreach (KeyValuePair<Key, Partial> kv in _pending)
                if (kv.Value.Deadline <= now) (dead ??= new List<Key>()).Add(kv.Key);
            if (dead != null)
                foreach (Key k in dead) _pending.Remove(k);
        }

        void EvictOldest()
        {
            Key oldest = default;
            long min = long.MaxValue;
            bool found = false;
            foreach (KeyValuePair<Key, Partial> kv in _pending)
                if (kv.Value.FirstSeenTicks < min) { min = kv.Value.FirstSeenTicks; oldest = kv.Key; found = true; }
            if (found) _pending.Remove(oldest);
        }

        /// <summary>Identifies a datagram being reassembled: (source, destination, protocol, identification).</summary>
        readonly struct Key : IEquatable<Key>
        {
            readonly uint _source;
            readonly uint _destination;
            readonly ushort _identification;
            readonly byte _protocol;

            Key(uint source, uint destination, ushort identification, byte protocol)
            {
                _source = source;
                _destination = destination;
                _identification = identification;
                _protocol = protocol;
            }

            public static Key From(ReadOnlySpan<byte> span)
            {
                uint source = (uint)((span[12] << 24) | (span[13] << 16) | (span[14] << 8) | span[15]);
                uint destination = (uint)((span[16] << 24) | (span[17] << 16) | (span[18] << 8) | span[19]);
                ushort id = (ushort)((span[4] << 8) | span[5]);
                return new Key(source, destination, id, span[9]);
            }

            public bool Equals(Key other) =>
                _source == other._source && _destination == other._destination &&
                _identification == other._identification && _protocol == other._protocol;

            public override bool Equals(object? obj) => obj is Key other && Equals(other);

            public override int GetHashCode()
            {
                unchecked
                {
                    int hash = (int)_source;
                    hash = hash * 397 ^ (int)_destination;
                    hash = hash * 397 ^ _identification;
                    hash = hash * 397 ^ _protocol;
                    return hash;
                }
            }
        }

        /// <summary>One datagram under reassembly: the staging buffer plus the coalesced received byte ranges.</summary>
        sealed class Partial
        {
            readonly List<(int Start, int End)> _intervals = new List<(int, int)>();

            public Partial(long deadline, long firstSeenTicks)
            {
                Deadline = deadline;
                FirstSeenTicks = firstSeenTicks;
            }

            /// <summary>Monotonic tick after which this incomplete datagram is discarded.</summary>
            public long Deadline { get; }

            /// <summary>Monotonic tick of the first fragment seen — used to evict the oldest datagram when over capacity.</summary>
            public long FirstSeenTicks { get; }

            /// <summary>Total payload length once the last fragment (More-Fragments cleared) has been seen, else -1.</summary>
            public int TotalLength { get; set; } = -1;

            /// <summary>Staging buffer holding received payload bytes at their datagram offsets; grows on demand.</summary>
            public byte[] Buffer { get; private set; } = Array.Empty<byte>();

            /// <summary>The datagram is whole when the last fragment is in and the received ranges cover [0, TotalLength).</summary>
            public bool IsComplete =>
                TotalLength >= 0 && _intervals.Count == 1 && _intervals[0].Start == 0 && _intervals[0].End == TotalLength;

            public void Add(int start, int end, ReadOnlySpan<byte> data)
            {
                if (Buffer.Length < end)
                {
                    byte[] grown = new byte[end];
                    Array.Copy(Buffer, grown, Buffer.Length);
                    Buffer = grown;
                }
                data.CopyTo(Buffer.AsSpan(start, end - start));
                Coalesce(start, end);
            }

            void Coalesce(int start, int end)
            {
                _intervals.Add((start, end));
                _intervals.Sort((a, b) => a.Start.CompareTo(b.Start));
                int write = 0;
                for (int read = 1; read < _intervals.Count; read++)
                {
                    (int Start, int End) current = _intervals[write];
                    (int Start, int End) next = _intervals[read];
                    if (next.Start <= current.End) // overlapping or touching → merge
                        _intervals[write] = (current.Start, Math.Max(current.End, next.End));
                    else
                        _intervals[++write] = next;
                }
                _intervals.RemoveRange(write + 1, _intervals.Count - (write + 1));
            }
        }
    }
}
