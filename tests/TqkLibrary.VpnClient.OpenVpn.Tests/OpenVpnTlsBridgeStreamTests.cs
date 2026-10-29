using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// The sync surface of <see cref="OpenVpnTlsBridgeStream"/> (driven by the blocking BouncyCastle TLS engine in
    /// tls-ekm mode) must really block on the bridge's own monitor/gate and call the SYNC sender on the caller's thread,
    /// wake on inbound/close/dispose, and never interleave records with the async path.
    /// </summary>
    public class OpenVpnTlsBridgeStreamTests
    {
        static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

        static OpenVpnTlsBridgeStream Bridge(OpenVpnTlsBridgeStream.SendTlsSync? sync = null,
            Func<ReadOnlyMemory<byte>, CancellationToken, Task>? async = null)
            => new(sync ?? (_ => { }), async ?? ((_, _) => Task.CompletedTask));

        [Fact]
        public async Task SyncRead_BlocksUntilInboundArrives()
        {
            using var bridge = Bridge();
            byte[] buffer = new byte[16];
            Task<int> read = Task.Run(() => bridge.Read(buffer, 0, buffer.Length));

            await Task.Delay(150);
            Assert.False(read.IsCompleted);

            bridge.EnqueueInbound(new byte[] { 1, 2, 3 });
            Assert.Same(read, await Task.WhenAny(read, Task.Delay(Timeout)));
            Assert.Equal(3, await read);
            Assert.Equal(new byte[] { 1, 2, 3 }, buffer.Take(3).ToArray());
        }

        [Fact]
        public async Task SyncRead_ReturnsPartialChunks_ThenZeroAfterCompleteInbound()
        {
            using var bridge = Bridge();
            bridge.EnqueueInbound(new byte[] { 1, 2, 3, 4, 5 });
            byte[] buffer = new byte[2];
            Assert.Equal(2, bridge.Read(buffer, 0, 2));
            Assert.Equal(2, bridge.Read(buffer, 0, 2));
            Assert.Equal(1, bridge.Read(buffer, 0, 2));

            Task<int> read = Task.Run(() => bridge.Read(buffer, 0, 2));
            await Task.Delay(100);
            Assert.False(read.IsCompleted);
            bridge.CompleteInbound();
            Assert.Same(read, await Task.WhenAny(read, Task.Delay(Timeout)));
            Assert.Equal(0, await read);
        }

        [Fact]
        public async Task SyncAndAsyncRead_BlockedReaders_ReturnZeroOnDispose()
        {
            var bridge = Bridge();
            Task<int> syncRead = Task.Run(() => bridge.Read(new byte[4], 0, 4));
            await Task.Delay(100);
            Assert.False(syncRead.IsCompleted);

            bridge.Dispose();
            Assert.Same(syncRead, await Task.WhenAny(syncRead, Task.Delay(Timeout)));
            Assert.Equal(0, await syncRead);
        }


        [Fact]
        public async Task SyncWrite_CallsSyncSenderOnCallingThread_NotTheAsyncOne()
        {
            int senderThread = -1, asyncCalls = 0;
            byte[]? seen = null;
            using var bridge = Bridge(
                sync: data => { senderThread = Environment.CurrentManagedThreadId; seen = data.ToArray(); },
                async: (_, _) => { Interlocked.Increment(ref asyncCalls); return Task.CompletedTask; });

            int callerThread = await Task.Run(() =>
            {
                bridge.Write(new byte[] { 9, 8, 7 }, 0, 3);
                return Environment.CurrentManagedThreadId;
            }).WaitAsync(Timeout);

            Assert.Equal(callerThread, senderThread);
            Assert.Equal(new byte[] { 9, 8, 7 }, seen);
            Assert.Equal(0, asyncCalls);
        }

        [Fact]
        public async Task ConcurrentSyncAndAsyncWrites_NeverOverlap()
        {
            int inFlight = 0, overlapped = 0, total = 0;
            void Enter() { if (Interlocked.Increment(ref inFlight) > 1) Interlocked.Exchange(ref overlapped, 1); }
            void Leave() { Interlocked.Increment(ref total); Interlocked.Decrement(ref inFlight); }
            using var bridge = Bridge(
                sync: _ => { Enter(); Thread.Sleep(2); Leave(); },
                async: async (_, ct) => { Enter(); await Task.Delay(2, ct); Leave(); });

            var writers = new List<Task>();
            for (int w = 0; w < 4; w++)
            {
                writers.Add(Task.Run(() => { for (int i = 0; i < 10; i++) bridge.Write(new byte[] { 1 }, 0, 1); }));
                writers.Add(Task.Run(async () => { for (int i = 0; i < 10; i++) await bridge.WriteAsync(new byte[] { 2 }, 0, 1); }));
            }
            await Task.WhenAll(writers).WaitAsync(Timeout);

            Assert.Equal(80, total);
            Assert.Equal(0, overlapped);
        }

        [Fact]
        public async Task SyncWrite_SenderFailure_SurfacesOnThatWrite_AndLaterWritesFail()
        {
            using var bridge = Bridge(sync: _ => throw new InvalidOperationException("boom"));
            var ex = Assert.Throws<InvalidOperationException>(() => bridge.Write(new byte[] { 1 }, 0, 1));
            Assert.Equal("boom", ex.Message);

            var later = await Assert.ThrowsAsync<IOException>(() => bridge.WriteAsync(new byte[] { 2 }, 0, 1).WaitAsync(Timeout));
            Assert.IsType<InvalidOperationException>(later.InnerException);
            Assert.Throws<IOException>(() => bridge.Write(new byte[] { 3 }, 0, 1));
        }

        [Fact]
        public async Task WriteAsync_CancelledAfterSenderStarted_FaultsStream()
        {
            var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var bridge = Bridge(async: async (_, ct) => { started.TrySetResult(true); await Task.Delay(System.Threading.Timeout.Infinite, ct); });
            using var cts = new CancellationTokenSource();
            Task write = bridge.WriteAsync(new byte[] { 1 }, 0, 1, cts.Token);
            await started.Task.WaitAsync(Timeout);
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => write.WaitAsync(Timeout));

            // A partial record may be on the wire: the stream is corrupt now.
            Assert.Throws<IOException>(() => bridge.Write(new byte[] { 2 }, 0, 1));
        }

        [Fact]
        public async Task WriteAsync_CancelledBeforeStart_DoesNotFaultStream()
        {
            var release = new ManualResetEventSlim();
            int syncCalls = 0;
            using var bridge = Bridge(sync: _ => { Interlocked.Increment(ref syncCalls); release.Wait(Timeout); });

            Task holder = Task.Run(() => bridge.Write(new byte[] { 1 }, 0, 1)); // holds the gate
            await Task.Delay(100);
            using var cts = new CancellationTokenSource();
            Task queued = bridge.WriteAsync(new byte[] { 2 }, 0, 1, cts.Token); // waits for the gate
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued.WaitAsync(Timeout));

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => bridge.WriteAsync(new byte[] { 3 }, 0, 1, new CancellationToken(true)));

            release.Set();
            await holder.WaitAsync(Timeout);
            bridge.Write(new byte[] { 4 }, 0, 1); // still healthy
            Assert.Equal(2, syncCalls);
        }

        [Fact]
        public async Task SyncWrite_BlockedOnGate_IsReleasedByDispose_AndWriteAfterDisposeThrows()
        {
            var release = new ManualResetEventSlim();
            var bridge = Bridge(sync: _ => release.Wait(Timeout));
            Task holder = Task.Run(() => bridge.Write(new byte[] { 1 }, 0, 1)); // inside the sender
            await Task.Delay(100);
            Task blocked = Task.Run(() => bridge.Write(new byte[] { 2 }, 0, 1)); // parked on the gate
            await Task.Delay(100);
            Assert.False(blocked.IsCompleted);

            bridge.Dispose();
            Assert.Same(blocked, await Task.WhenAny(blocked, Task.Delay(Timeout)));
            await Assert.ThrowsAsync<ObjectDisposedException>(() => blocked);
            Assert.Throws<ObjectDisposedException>(() => bridge.Write(new byte[] { 3 }, 0, 1));

            release.Set();
            await holder.WaitAsync(Timeout);
        }
    }
}
