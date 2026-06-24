using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Diagnostics;
using TqkLibrary.VpnClient.Ppp;
using Xunit;

namespace TqkLibrary.VpnClient.Ppp.Tests
{
    /// <summary>
    /// Pins the optional <see cref="ILogger"/> the deep PPP layer takes (roadmap Q.2): an injected logger must see the
    /// LCP/IPCP option-negotiation <see cref="VpnEventIds.ProtocolStep"/> traces (Configure-Request, Opened, link up) as
    /// two engines bring a link up over the loopback channel — while a null logger negotiates the same link.
    /// </summary>
    public class PppEngineLoggingTests
    {
        static readonly IPAddress ClientIp = IPAddress.Parse("10.0.0.2");
        static readonly IPAddress ServerIp = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress Dns = IPAddress.Parse("8.8.8.8");

        [Fact]
        public void LinkUp_WithLogger_EmitsLcpAndIpcpProtocolSteps()
        {
            var (ca, cb) = LoopbackPppChannel.CreatePair();
            var log = new CapturingLogger();

            var client = new PppEngine(ca, magic: 0x11111111, localAddress: IPAddress.Any, logger: log);
            var server = new PppEngine(cb, magic: 0x22222222, localAddress: ServerIp, assignPeerAddress: ClientIp, assignPeerDns: Dns);

            client.Start();
            server.Start();
            LoopbackPppChannel.Pump(ca, cb);

            Assert.True(client.IsLinkUp);
            Assert.True(log.Captured(VpnEventIds.ProtocolStep));
            IReadOnlyList<string> steps = log.MessagesFor(VpnEventIds.ProtocolStep);
            // The client's LCP and IPCP both negotiate and open; the engine logs the IPCP-driven link-up too.
            Assert.Contains(steps, m => m.Contains("[ppp.lcp]") && m.Contains("Opened"));
            Assert.Contains(steps, m => m.Contains("[ppp.ipcp]") && m.Contains("Opened"));
            Assert.Contains(steps, m => m.Contains("[ppp]") && m.Contains("link up"));
        }

        [Fact]
        public void LinkUp_NullLogger_NegotiatesSameLink()
        {
            var (ca, cb) = LoopbackPppChannel.CreatePair();

            var client = new PppEngine(ca, magic: 0x11111111, localAddress: IPAddress.Any, logger: null);
            var server = new PppEngine(cb, magic: 0x22222222, localAddress: ServerIp, assignPeerAddress: ClientIp, assignPeerDns: Dns);

            client.Start();
            server.Start();
            LoopbackPppChannel.Pump(ca, cb);

            Assert.True(client.IsLinkUp);
            Assert.Equal(ClientIp, client.AssignedAddress);
            Assert.Equal(Dns, client.AssignedDns);
        }

        sealed class CapturingLogger : ILogger
        {
            readonly ConcurrentQueue<(EventId Id, string Message)> _entries = new();

            public bool Captured(EventId id) => _entries.Any(e => e.Id.Id == id.Id);
            public IReadOnlyList<string> MessagesFor(EventId id)
                => _entries.Where(e => e.Id.Id == id.Id).Select(e => e.Message).ToArray();

            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true; // capture everything, including Trace-level ProtocolStep

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
                => _entries.Enqueue((eventId, formatter(state, exception)));
        }
    }
}
