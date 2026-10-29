using System;
using System.Collections.Generic;
using System.IO;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.Dtls.Tests
{
    /// <summary>
    /// BouncyCastle's DTLS record layer calls <see cref="BouncyCastleDatagramBridge.Send(byte[],int,int)"/> synchronously
    /// on its I/O thread: the bridge must queue instead of blocking on the async inner send, and still deliver in order.
    /// </summary>
    public class BouncyCastleDatagramBridgeTests
    {
        /// <summary>Inner pipe whose sends park until <see cref="Release"/>; receives never complete until cancelled.</summary>
        sealed class GatedTransport : IDatagramTransport
        {
            readonly TaskCompletionSource<bool> _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public readonly List<byte[]> Sent = new();
            public int SendCalls;

            public void Release() => _gate.TrySetResult(true);

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public async ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
            {
                Interlocked.Increment(ref SendCalls);
                await _gate.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                lock (Sent) Sent.Add(datagram.ToArray());
            }

            public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
                return 0;
            }

            public ValueTask DisposeAsync() => default;
        }

        [Fact]
        public async Task Send_DoesNotBlockOnInnerSend_AndDeliversInOrder()
        {
            var inner = new GatedTransport();
            var bridge = new BouncyCastleDatagramBridge(inner);
            try
            {
                byte[] buffer = new byte[8];
                var sw = Stopwatch.StartNew();
                for (byte i = 0; i < 20; i++)
                {
                    buffer[0] = i; // BouncyCastle reuses its buffer: the bridge must have copied the previous datagram
                    bridge.Send(buffer, 0, 1);
                }
                Assert.True(sw.Elapsed < TimeSpan.FromSeconds(1), "Send blocked on the gated inner transport");
                Assert.Empty(inner.Sent);

                inner.Release();
                var deadline = DateTime.UtcNow.AddSeconds(5);
                while (DateTime.UtcNow < deadline) { lock (inner.Sent) if (inner.Sent.Count == 20) break; await Task.Delay(10); }

                lock (inner.Sent)
                    Assert.Equal(Enumerable.Range(0, 20).Select(x => (byte)x), inner.Sent.Select(d => Assert.Single(d)));
            }
            finally { bridge.Close(); }
        }

        [Fact]
        public void Close_WithInnerSendStuck_ReturnsAndLaterSendsThrow()
        {
            var inner = new GatedTransport(); // never released
            var bridge = new BouncyCastleDatagramBridge(inner);
            bridge.Send(new byte[] { 1 }, 0, 1);

            var sw = Stopwatch.StartNew();
            bridge.Close();
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), "Close hung on a stuck inner send");

            // Like a send on a closed socket (the old inline SendAsync): BouncyCastle must see a failure, not silence.
            Assert.Throws<ObjectDisposedException>(() => bridge.Send(new byte[] { 2 }, 0, 1));
            Assert.Empty(inner.Sent);
            bridge.Close(); // idempotent
        }

        /// <summary>Inner pipe whose every send fails.</summary>
        sealed class FailingTransport : IDatagramTransport
        {
            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;
            public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
                => new ValueTask(Task.FromException(new InvalidOperationException("link down")));
            public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
                return 0;
            }
            public ValueTask DisposeAsync() => default;
        }

        [Fact]
        public async Task InnerSendFailure_SurfacesOnNextSend()
        {
            var bridge = new BouncyCastleDatagramBridge(new FailingTransport());
            try
            {
                bridge.Send(new byte[] { 1 }, 0, 1); // queued; the pump's send fails in the background
                IOException? ex = null;
                var deadline = DateTime.UtcNow.AddSeconds(5);
                while (ex is null && DateTime.UtcNow < deadline)
                {
                    try { bridge.Send(new byte[] { 2 }, 0, 1); await Task.Delay(10); }
                    catch (IOException e) { ex = e; }
                }
                Assert.NotNull(ex);
                Assert.IsType<InvalidOperationException>(ex!.InnerException);
                Assert.Equal("link down", ex.InnerException!.Message);
            }
            finally { bridge.Close(); }
        }
    }
}
