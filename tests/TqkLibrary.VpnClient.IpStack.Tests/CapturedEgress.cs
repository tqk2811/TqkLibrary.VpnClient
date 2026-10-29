using TqkLibrary.VpnClient.IpStack;

namespace TqkLibrary.VpnClient.IpStack.Tests
{
    /// <summary>
    /// Outbound packets recorded by a test channel. A packet may reach the channel from an asynchronous egress drain
    /// rather than inline in the call that produced it, so <see cref="Settle"/> first waits on the stack's
    /// <see cref="TcpIpStack.FlushEgressAsync"/> barrier — everything the stack accepted before the call has been
    /// written — then snapshots. Deterministic for "exactly one reply" and for "nothing sent" alike.
    /// </summary>
    internal sealed class CapturedEgress
    {
        const int GuardMs = 5000;

        readonly List<byte[]> _packets = new();
        TcpIpStack? _stack;

        /// <summary>
        /// Called from the test channel's <c>InboundIpPacket</c> add accessor: the subscriber is the stack's own
        /// handler, so its target is the stack whose egress <see cref="Settle"/> must flush.
        /// </summary>
        public void Observe(Delegate? subscriber)
        {
            if (subscriber?.Target is TcpIpStack stack) _stack = stack;
        }

        public void Add(ReadOnlyMemory<byte> ipPacket)
        {
            byte[] copy = ipPacket.ToArray();
            lock (_packets) _packets.Add(copy);
        }

        public int Count { get { lock (_packets) return _packets.Count; } }

        /// <summary>Waits for the stack's egress to flush, then returns a snapshot of everything sent so far.</summary>
        public List<byte[]> Settle()
        {
            if (_stack is null) throw new InvalidOperationException("No TcpIpStack subscribed to this channel.");
            if (!_stack.FlushEgressAsync().Wait(GuardMs)) throw new TimeoutException("The stack's egress did not flush.");
            lock (_packets) return new List<byte[]>(_packets);
        }
    }
}
