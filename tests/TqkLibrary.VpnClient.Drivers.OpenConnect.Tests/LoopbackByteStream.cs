using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Tests
{
    /// <summary>
    /// An in-memory, lossless, ordered duplex byte pipe — two <see cref="IByteStreamTransport"/> ends whose writes land
    /// on the peer's read buffer. It stands in for the TLS byte stream so the whole OpenConnect driver (HTTP auth +
    /// CONNECT + CSTP framing) can be driven offline. Throwaway test scaffolding: the library is a client; the ocserv
    /// responder role exists only here.
    /// </summary>
    sealed class LoopbackByteStreamPair
    {
        public LoopbackByteStreamPair()
        {
            var clientToServer = Channel.CreateUnbounded<byte[]>();
            var serverToClient = Channel.CreateUnbounded<byte[]>();
            Client = new End(write: serverToClient.Writer, read: serverToClient.Reader, peerWrite: clientToServer.Writer);
            Server = new End(write: clientToServer.Writer, read: clientToServer.Reader, peerWrite: serverToClient.Writer);
        }

        /// <summary>The client end (the driver's transport).</summary>
        public End Client { get; }

        /// <summary>The server end (the ocserv responder's transport).</summary>
        public End Server { get; }

        /// <summary>One end of the pipe: it reads from its own inbound channel and writes onto the peer's inbound channel.</summary>
        public sealed class End : IByteStreamTransport
        {
            // "read" is this end's inbound channel; "peerWrite" is where this end's writes go (the peer's inbound).
            readonly ChannelWriter<byte[]> _peerWrite;
            readonly ChannelReader<byte[]> _read;
            byte[] _leftover = Array.Empty<byte>();
            int _leftoverOffset;

            internal End(ChannelWriter<byte[]> write, ChannelReader<byte[]> read, ChannelWriter<byte[]> peerWrite)
            {
                _ = write; // unused on this end; kept for symmetry/readability
                _read = read;
                _peerWrite = peerWrite;
            }

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            {
                _peerWrite.TryWrite(buffer.ToArray());
                return default;
            }

            public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (_leftoverOffset >= _leftover.Length)
                {
                    // Block until the next chunk arrives (or the stream closes / cancels).
                    byte[] chunk;
                    try { chunk = await _read.ReadAsync(cancellationToken).ConfigureAwait(false); }
                    catch (ChannelClosedException) { return 0; }
                    _leftover = chunk;
                    _leftoverOffset = 0;
                }
                int n = Math.Min(buffer.Length, _leftover.Length - _leftoverOffset);
                _leftover.AsMemory(_leftoverOffset, n).CopyTo(buffer);
                _leftoverOffset += n;
                return n;
            }

            public ValueTask DisposeAsync()
            {
                _peerWrite.TryComplete(); // closing one end's writes surfaces as EOF on the peer's reads
                return default;
            }
        }
    }

    /// <summary>An <see cref="IOpenConnectTransportFactory"/> that hands back a fixed in-process byte-stream end.</summary>
    sealed class InProcessOpenConnectTransportFactory : Drivers.OpenConnect.Transport.IOpenConnectTransportFactory
    {
        readonly IByteStreamTransport _end;
        public InProcessOpenConnectTransportFactory(IByteStreamTransport end) => _end = end;

        public Task<Drivers.OpenConnect.Transport.OpenConnectTransportHandle> ConnectAsync(
            string host, System.Net.IPEndPoint remote, CancellationToken cancellationToken)
            => Task.FromResult(new Drivers.OpenConnect.Transport.OpenConnectTransportHandle(_end));
    }
}
