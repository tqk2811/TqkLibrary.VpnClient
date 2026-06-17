using System;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.OpenConnect.Transport;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Tests
{
    /// <summary>
    /// An in-memory, connected datagram pipe with two ends (client/server) whose <see cref="IDatagramTransport.SendAsync"/>
    /// delivers one datagram to the peer's inbound queue — preserving boundaries like UDP. It stands in for the
    /// gateway's DTLS UDP socket so the whole OpenConnect DTLS data path (UDP → DTLS handshake → CSTP-over-DTLS) can be
    /// driven offline. Throwaway test scaffolding standing in for a real UDP socket.
    /// </summary>
    sealed class LoopbackDatagramLink
    {
        public LoopbackDatagramLink()
        {
            var c2s = Channel.CreateUnbounded<byte[]>();
            var s2c = Channel.CreateUnbounded<byte[]>();
            Client = new End(inbound: s2c, peerInbound: c2s);
            Server = new End(inbound: c2s, peerInbound: s2c);
        }

        /// <summary>The client end (the driver's plaintext UDP pipe, wrapped in DTLS by the connection).</summary>
        public End Client { get; }

        /// <summary>The server end (the BouncyCastle DTLS server's pipe).</summary>
        public End Server { get; }

        /// <summary>One end of the datagram pipe: reads its inbound channel, writes to the peer's inbound channel.</summary>
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
                _peerInbound.Writer.TryComplete(); // closing one end surfaces as EOF on the peer's reads
                return default;
            }
        }
    }

    /// <summary>An <see cref="IOpenConnectDatagramTransportFactory"/> that hands back a fixed in-process datagram end.</summary>
    sealed class InProcessOpenConnectDatagramTransportFactory : IOpenConnectDatagramTransportFactory
    {
        readonly IDatagramTransport _end;
        public InProcessOpenConnectDatagramTransportFactory(IDatagramTransport end) => _end = end;

        public Task<IDatagramTransport> ConnectAsync(string host, IPEndPoint remote, CancellationToken cancellationToken)
            => Task.FromResult(_end);
    }
}
