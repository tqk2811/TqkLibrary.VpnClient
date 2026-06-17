using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Tests
{
    /// <summary>
    /// A minimal in-memory <see cref="ILoggerFactory"/> the offline tests inject to capture the diagnostic events the
    /// driver emits (handshake/NCP/keepalive/reconnect/drop). It records every entry's <see cref="EventId"/> and
    /// formatted message so a test can assert that an expected event fired — without touching the console or any sink.
    /// </summary>
    sealed class CapturingLoggerFactory : ILoggerFactory
    {
        readonly ConcurrentQueue<(EventId Id, LogLevel Level, string Message)> _entries = new();

        public IReadOnlyList<(EventId Id, LogLevel Level, string Message)> Entries => _entries.ToArray();

        /// <summary>True once at least one entry with the given event id has been captured.</summary>
        public bool Captured(EventId id) => _entries.Any(e => e.Id.Id == id.Id);

        /// <summary>The captured messages for the given event id (in order).</summary>
        public IReadOnlyList<string> MessagesFor(EventId id)
            => _entries.Where(e => e.Id.Id == id.Id).Select(e => e.Message).ToArray();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(_entries);

        public void AddProvider(ILoggerProvider provider) { /* not needed for the test sink */ }

        public void Dispose() { }

        sealed class CapturingLogger : ILogger
        {
            readonly ConcurrentQueue<(EventId, LogLevel, string)> _sink;
            public CapturingLogger(ConcurrentQueue<(EventId, LogLevel, string)> sink) => _sink = sink;

            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true; // capture everything so Trace-level keepalive entries land too

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
                => _sink.Enqueue((eventId, logLevel, formatter(state, exception)));
        }
    }
}
