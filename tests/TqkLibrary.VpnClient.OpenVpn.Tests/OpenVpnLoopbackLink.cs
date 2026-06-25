namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>An in-memory OpenVPN packet link; each side delivers to the other in send order on the thread pool. Test-only.</summary>
    sealed class OpenVpnLoopbackLink
    {
        readonly Endpoint _client = new();
        readonly Endpoint _server = new();

        public OpenVpnLoopbackLink()
        {
            _client.Peer = _server;
            _server.Peer = _client;
        }

        public IOpenVpnTransport Client => _client;
        public IOpenVpnTransport Server => _server;

        sealed class Endpoint : IOpenVpnTransport
        {
            public Endpoint? Peer;
            public event Action<ReadOnlyMemory<byte>>? DatagramReceived;
            readonly object _lock = new();
            Task _tail = Task.CompletedTask;

            public Task SendAsync(ReadOnlyMemory<byte> packet)
            {
                byte[] copy = packet.ToArray();
                Endpoint? peer = Peer;
                if (peer != null)
                    lock (peer._lock)
                        peer._tail = peer._tail.ContinueWith(_ => peer.DatagramReceived?.Invoke(copy), TaskScheduler.Default);
                return Task.CompletedTask;
            }
        }
    }
}
