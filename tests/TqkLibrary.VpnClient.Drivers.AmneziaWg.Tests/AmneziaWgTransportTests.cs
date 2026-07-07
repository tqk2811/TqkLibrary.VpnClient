using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Drivers.AmneziaWg.Models;
using TqkLibrary.VpnClient.Drivers.WireGuard.Transport;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.AmneziaWg.Tests
{
    /// <summary>
    /// Tests for the transport decorators: the datagram-transport wrapper (<see cref="AmneziaWgDatagramTransport"/>) over
    /// an in-memory loopback, and the factory decorator (<see cref="AmneziaWgTransportFactory"/>) wrapping a fake base
    /// WireGuard transport factory (inbound de-obfuscation + junk drop, outbound obfuscation + junk burst).
    /// </summary>
    public class AmneziaWgTransportTests
    {
        static AmneziaWgObfuscator DeterministicObfuscator() =>
            new AmneziaWgObfuscator(AmneziaWgTestSupport.SampleParameters(), new DeterministicRandom());

        [Fact]
        public async Task DatagramTransport_RoundTripsWireGuardDatagrams_AndDropsJunkBurst()
        {
            var pipeA = new InMemoryDatagram();
            var pipeB = new InMemoryDatagram();
            pipeA.ConnectTo(pipeB);
            pipeB.ConnectTo(pipeA);

            await using var a = new AmneziaWgDatagramTransport(pipeA, DeterministicObfuscator());
            await using var b = new AmneziaWgDatagramTransport(pipeB, DeterministicObfuscator());

            byte[] init = AmneziaWgTestSupport.WgDatagram(1, 148); // first init ⇒ preceded by Jc junk packets on the wire
            byte[] data = AmneziaWgTestSupport.WgDatagram(4, 60);

            await a.SendAsync(init, TestContext.Current.CancellationToken);
            await a.SendAsync(data, TestContext.Current.CancellationToken);

            // B's receive loop drops the Jc junk packets and yields the two real WireGuard datagrams in order.
            byte[] buffer = new byte[65535];
            int n1 = await ReceiveWithTimeout(b, buffer);
            byte[] first = buffer.AsSpan(0, n1).ToArray();
            int n2 = await ReceiveWithTimeout(b, buffer);
            byte[] second = buffer.AsSpan(0, n2).ToArray();

            Assert.Equal(init, first);
            Assert.Equal(data, second);
        }

        [Fact]
        public async Task DatagramTransport_EmitsJunkBurst_OnlyBeforeFirstInitiation()
        {
            var pipe = new InMemoryDatagram();
            await using var transport = new AmneziaWgDatagramTransport(pipe, DeterministicObfuscator());
            int jc = AmneziaWgTestSupport.SampleParameters().Jc;

            await transport.SendAsync(AmneziaWgTestSupport.WgDatagram(1, 148), TestContext.Current.CancellationToken); // Jc junk + 1 obfuscated init
            Assert.Equal(jc + 1, pipe.Sent.Count);

            await transport.SendAsync(AmneziaWgTestSupport.WgDatagram(4, 60), TestContext.Current.CancellationToken); // data ⇒ no junk burst
            Assert.Equal(jc + 2, pipe.Sent.Count);

            await transport.SendAsync(AmneziaWgTestSupport.WgDatagram(1, 148), TestContext.Current.CancellationToken); // second init ⇒ no junk burst
            Assert.Equal(jc + 3, pipe.Sent.Count);
        }

        [Fact]
        public async Task Factory_InboundReceiver_Deobfuscates_AndDropsJunk()
        {
            var baseFactory = new FakeBaseFactory();
            var factory = new AmneziaWgTransportFactory(baseFactory, AmneziaWgTestSupport.SampleParameters(), new DeterministicRandom());
            WireGuardTransportHandle handle = await factory.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 51820), TestContext.Current.CancellationToken);

            var received = new List<byte[]>();
            handle.SetReceiver(d => received.Add(d.ToArray()));

            var obf = DeterministicObfuscator();
            byte[] wg = AmneziaWgTestSupport.WgDatagram(4, 60);

            baseFactory.SimulateInbound(obf.Obfuscate(wg)); // real ⇒ delivered de-obfuscated
            baseFactory.SimulateInbound(new byte[30]);      // junk ⇒ dropped

            Assert.Single(received);
            Assert.Equal(wg, received[0]);
        }

        [Fact]
        public async Task Factory_OutboundDatagram_Obfuscates_WithJunkBurstBeforeFirstInit()
        {
            var baseFactory = new FakeBaseFactory();
            var factory = new AmneziaWgTransportFactory(baseFactory, AmneziaWgTestSupport.SampleParameters(), new DeterministicRandom());
            WireGuardTransportHandle handle = await factory.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 51820), TestContext.Current.CancellationToken);

            int jc = AmneziaWgTestSupport.SampleParameters().Jc;
            var expected = DeterministicObfuscator();

            byte[] init = AmneziaWgTestSupport.WgDatagram(1, 148);
            await handle.Datagram.SendAsync(init, TestContext.Current.CancellationToken);

            // Jc junk packets then the obfuscated initiation reached the base transport.
            Assert.Equal(jc + 1, baseFactory.Transport.Sent.Count);
            Assert.Equal(expected.Obfuscate(init), baseFactory.Transport.Sent[jc]);
        }

        [Fact]
        public async Task Factory_PassesThroughReceivePump()
        {
            Func<CancellationToken, Task> pump = _ => Task.CompletedTask;
            var baseFactory = new FakeBaseFactory(pump);
            var factory = new AmneziaWgTransportFactory(baseFactory, AmneziaWgTestSupport.SampleParameters());

            WireGuardTransportHandle handle = await factory.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 51820), TestContext.Current.CancellationToken);

            Assert.Same(pump, handle.ReceivePump);
        }

        static async Task<int> ReceiveWithTimeout(AmneziaWgDatagramTransport transport, Memory<byte> buffer)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            return await transport.ReceiveAsync(buffer, cts.Token);
        }

        /// <summary>A minimal base <see cref="IWireGuardTransportFactory"/> returning an in-memory transport whose
        /// registered receiver can be driven directly to simulate inbound wire datagrams.</summary>
        sealed class FakeBaseFactory : IWireGuardTransportFactory
        {
            readonly Func<CancellationToken, Task>? _pump;
            Action<ReadOnlyMemory<byte>>? _receiver;

            public FakeBaseFactory(Func<CancellationToken, Task>? pump = null) => _pump = pump;

            public InMemoryDatagram Transport { get; } = new InMemoryDatagram();

            public Task<WireGuardTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
            {
                var handle = new WireGuardTransportHandle(Transport, r => _receiver = r, _pump);
                return Task.FromResult(handle);
            }

            /// <summary>Invokes the wired receiver (the factory's de-obfuscating wrapper) with a raw wire datagram.</summary>
            public void SimulateInbound(byte[] wire) => _receiver?.Invoke(wire);
        }
    }
}
