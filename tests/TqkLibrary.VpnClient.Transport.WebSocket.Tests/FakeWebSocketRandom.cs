using System;
using TqkLibrary.VpnClient.Transport.WebSocket;

namespace TqkLibrary.VpnClient.Transport.WebSocket.Tests
{
    /// <summary>
    /// Deterministic <see cref="IWebSocketRandom"/> for tests: every requested byte is a running counter, so the
    /// handshake key and per-frame mask keys are exactly predictable (lets a test assert the produced
    /// <c>Sec-WebSocket-Key</c>). Value content is irrelevant to correctness — a masked frame round-trips through any key.
    /// </summary>
    sealed class FakeWebSocketRandom : IWebSocketRandom
    {
        byte _next;

        public FakeWebSocketRandom(byte seed = 0) { _next = seed; }

        public byte[] NextBytes(int count)
        {
            byte[] buffer = new byte[count];
            for (int i = 0; i < count; i++) buffer[i] = _next++;
            return buffer;
        }
    }
}
