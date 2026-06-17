using System.Net;
using System.Net.Sockets;

namespace TqkLibrary.VpnClient.IpStack.Udp
{
    /// <summary>
    /// A userspace UDP socket bound to one local port on the tunnel address(es). Datagrams are sent immediately;
    /// inbound datagrams matching the local port are queued and surfaced by <see cref="ReceiveAsync"/>. No connection
    /// state — the remote endpoint is supplied per send and reported per receive. Dual-stack: the source address is
    /// chosen per send from the remote's address family.
    /// </summary>
    public sealed class UdpConnection
    {
        readonly IPAddress? _localV4;
        readonly IPAddress? _localV6;
        readonly Action<byte[]> _sendIp;
        readonly object _sync = new();
        readonly Queue<Datagram> _inbound = new();
        TaskCompletionSource<bool>? _waiter;
        ushort _identification;

        internal UdpConnection(IPAddress? localV4, IPAddress? localV6, ushort localPort, Action<byte[]> sendIp)
        {
            _localV4 = localV4;
            _localV6 = localV6;
            LocalPort = localPort;
            _sendIp = sendIp;
        }

        /// <summary>The bound local UDP port.</summary>
        public ushort LocalPort { get; }

        /// <summary>Sends <paramref name="data"/> to the given remote endpoint as one UDP datagram.</summary>
        public void SendTo(IPAddress remoteAddress, ushort remotePort, ReadOnlySpan<byte> data)
        {
            IPAddress? local = remoteAddress.AddressFamily == AddressFamily.InterNetworkV6 ? _localV6 : _localV4;
            if (local is null)
                throw new InvalidOperationException($"No local {remoteAddress.AddressFamily} address is bound on this UDP socket.");
            byte[] udp = UdpDatagram.Build(local, remoteAddress, LocalPort, remotePort, data);
            byte[] ip = IpLayer.Build(local, remoteAddress, Ipv4.ProtocolUdp, udp, _identification++); // UDP protocol number 17 is shared by IPv4/IPv6
            _sendIp(ip);
        }

        /// <summary>Receives the next inbound datagram, returning its data and source endpoint.</summary>
        public async Task<UdpReceiveResult> ReceiveAsync(CancellationToken cancellationToken = default)
        {
            while (true)
            {
                TaskCompletionSource<bool> waiter;
                lock (_sync)
                {
                    if (_inbound.Count > 0)
                    {
                        Datagram d = _inbound.Dequeue();
                        return new UdpReceiveResult(d.Data, d.RemoteAddress, d.RemotePort);
                    }
                    waiter = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    _waiter = waiter;
                }
                // Register against the local waiter, not the _waiter field: a datagram arriving on another thread
                // nulls the field (and completes this same TCS) before this line runs, which would otherwise hand the
                // callback a null and NRE on the cancelling thread (synchronously, if the token is already cancelled).
                using (cancellationToken.Register(static w => ((TaskCompletionSource<bool>)w!).TrySetResult(true), waiter))
                    await waiter.Task.ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
        }

        internal void OnDatagram(IPAddress remoteAddress, ushort remotePort, byte[] payload)
        {
            TaskCompletionSource<bool>? waiter;
            lock (_sync)
            {
                _inbound.Enqueue(new Datagram(payload, remoteAddress, remotePort));
                waiter = _waiter;
                _waiter = null;
            }
            waiter?.TrySetResult(true);
        }

        readonly struct Datagram
        {
            public Datagram(byte[] data, IPAddress remoteAddress, ushort remotePort)
            {
                Data = data; RemoteAddress = remoteAddress; RemotePort = remotePort;
            }
            public byte[] Data { get; }
            public IPAddress RemoteAddress { get; }
            public ushort RemotePort { get; }
        }
    }

    /// <summary>The data and source endpoint of a received UDP datagram.</summary>
    public readonly struct UdpReceiveResult
    {
        /// <summary>Creates a result.</summary>
        public UdpReceiveResult(byte[] data, IPAddress remoteAddress, ushort remotePort)
        {
            Data = data; RemoteAddress = remoteAddress; RemotePort = remotePort;
        }

        /// <summary>The datagram payload.</summary>
        public byte[] Data { get; }

        /// <summary>The source address.</summary>
        public IPAddress RemoteAddress { get; }

        /// <summary>The source port.</summary>
        public ushort RemotePort { get; }
    }
}
