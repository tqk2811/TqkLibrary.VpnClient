using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Pptp.Tests
{
    /// <summary>
    /// An in-memory, lossless, ordered duplex byte pipe — two <see cref="IByteStreamTransport"/> ends whose writes
    /// land on the peer's read buffer. Stands in for the TCP/1723 control connection so the PPTP control-connection
    /// state machine can be driven against a simulated PAC offline. Throwaway test scaffolding (the library is the
    /// PNS/client; the PAC responder role exists only here).
    /// </summary>
    sealed class LoopbackByteStreamPair
    {
        public LoopbackByteStreamPair()
        {
            var clientToServer = Channel.CreateUnbounded<byte[]>();
            var serverToClient = Channel.CreateUnbounded<byte[]>();
            Client = new End(serverToClient.Reader, clientToServer.Writer);
            Server = new End(clientToServer.Reader, serverToClient.Writer);
        }

        public End Client { get; }
        public End Server { get; }

        public sealed class End : IByteStreamTransport
        {
            readonly ChannelReader<byte[]> _read;
            readonly ChannelWriter<byte[]> _peerWrite;
            byte[] _leftover = Array.Empty<byte>();
            int _leftoverOffset;

            internal End(ChannelReader<byte[]> read, ChannelWriter<byte[]> peerWrite)
            {
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
                _peerWrite.TryComplete();
                return default;
            }
        }
    }
}
