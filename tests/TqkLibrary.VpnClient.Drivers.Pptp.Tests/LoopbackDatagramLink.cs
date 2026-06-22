using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Pptp.Tests
{
    /// <summary>
    /// An in-memory connected datagram pipe with two ends whose <see cref="IDatagramTransport.SendAsync"/> delivers
    /// one datagram to the peer's inbound queue, preserving boundaries like a raw-IP socket. Stands in for the
    /// proto-47 transport so the PPTP GRE data path can be driven offline. Throwaway test scaffolding. Replicated from
    /// the Pptp.Tests project's helper.
    /// </summary>
    sealed class LoopbackDatagramLink
    {
        public LoopbackDatagramLink()
        {
            var a2b = Channel.CreateUnbounded<byte[]>();
            var b2a = Channel.CreateUnbounded<byte[]>();
            A = new End(inbound: b2a, peerInbound: a2b);
            B = new End(inbound: a2b, peerInbound: b2a);
        }

        public End A { get; }
        public End B { get; }

        public sealed class End : IDatagramTransport
        {
            readonly Channel<byte[]> _inbound;
            readonly Channel<byte[]> _peerInbound;

            internal End(Channel<byte[]> inbound, Channel<byte[]> peerInbound)
            {
                _inbound = inbound;
                _peerInbound = peerInbound;
            }

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
            {
                _peerInbound.Writer.TryWrite(datagram.ToArray());
                return default;
            }

            public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                byte[] datagram;
                try { datagram = await _inbound.Reader.ReadAsync(cancellationToken).ConfigureAwait(false); }
                catch (ChannelClosedException) { return 0; }
                int n = Math.Min(buffer.Length, datagram.Length);
                datagram.AsMemory(0, n).CopyTo(buffer);
                return n;
            }

            public ValueTask DisposeAsync()
            {
                _peerInbound.Writer.TryComplete();
                return default;
            }
        }
    }
}
