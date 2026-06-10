using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;

namespace TqkLibrary.Vpn.IpStack.Tcp
{
    /// <summary>
    /// Binds an <see cref="IPacketChannel"/> and a local tunnel address, demultiplexes inbound TCP/UDP/ICMP packets
    /// to their connections by local port (echo by identifier for ICMP), and actively opens new TCP connections.
    /// </summary>
    public sealed class TcpIpStack
    {
        static readonly byte[] DefaultPingData = System.Text.Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwabcdefghi");

        readonly IPacketChannel _channel;
        readonly IPAddress _localAddress;
        readonly ConcurrentDictionary<ushort, TcpConnection> _connections = new();
        readonly ConcurrentDictionary<ushort, UdpConnection> _udpSockets = new();
        readonly ConcurrentDictionary<ushort, TaskCompletionSource<PingReply>> _pings = new();
        readonly Ipv4Reassembler _reassembler = new();
        readonly ushort _pingIdentifier;
        int _nextPort = 49152;
        int _nextPingSequence;
        int _icmpIpId;

        /// <summary>Creates the stack over the given channel, sourcing packets from <paramref name="localAddress"/>.</summary>
        public TcpIpStack(IPacketChannel channel, IPAddress localAddress)
        {
            _channel = channel;
            _localAddress = localAddress;
            byte[] id = new byte[2];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(id);
            _pingIdentifier = (ushort)((id[0] << 8) | id[1]);
            _channel.InboundIpPacket += OnInbound;
        }

        /// <summary>Opens a TCP connection to <paramref name="remoteAddress"/>:<paramref name="remotePort"/> through the tunnel.</summary>
        public async Task<TcpConnection> ConnectAsync(IPAddress remoteAddress, ushort remotePort, CancellationToken cancellationToken = default)
        {
            ushort localPort = (ushort)Interlocked.Increment(ref _nextPort);
            var connection = new TcpConnection(_localAddress, localPort, remoteAddress, remotePort, SendIp);
            _connections[localPort] = connection;
            connection.Closed += () => { _connections.TryRemove(localPort, out _); connection.Dispose(); }; // drop faulted connections (RST / RTO give-up)

            connection.StartConnect();

            Task completed = await Task.WhenAny(connection.Connected, Task.Delay(Timeout.Infinite, cancellationToken)).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            await connection.Connected.ConfigureAwait(false); // observe handshake result/fault
            return connection;
        }

        /// <summary>Binds a userspace UDP socket on an ephemeral local port for datagrams through the tunnel.</summary>
        public UdpConnection BindUdp() => BindUdp((ushort)Interlocked.Increment(ref _nextPort));

        /// <summary>Binds a userspace UDP socket on a specific local port.</summary>
        public UdpConnection BindUdp(ushort localPort)
        {
            var socket = new UdpConnection(_localAddress, localPort, SendIp);
            _udpSockets[localPort] = socket;
            return socket;
        }

        /// <summary>
        /// Sends an ICMP Echo Request through the tunnel and awaits the matching Echo Reply. Throws
        /// <see cref="IcmpUnreachableException"/> if the target replies Destination Unreachable, or
        /// <see cref="OperationCanceledException"/> if cancelled before a reply arrives.
        /// </summary>
        public async Task<PingReply> PingAsync(IPAddress remoteAddress, ReadOnlyMemory<byte> data = default, CancellationToken cancellationToken = default)
        {
            ushort sequence = (ushort)Interlocked.Increment(ref _nextPingSequence);
            var waiter = new TaskCompletionSource<PingReply>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pings[sequence] = waiter;
            try
            {
                ReadOnlySpan<byte> payload = data.IsEmpty ? DefaultPingData : data.Span;
                byte[] icmp = Icmpv4.BuildEcho(Icmpv4.TypeEchoRequest, _pingIdentifier, sequence, payload);
                byte[] ip = Ipv4.Build(_localAddress, remoteAddress, Ipv4.ProtocolIcmp, icmp, (ushort)Interlocked.Increment(ref _icmpIpId));

                var stopwatch = Stopwatch.StartNew();
                SendIp(ip);
                using (cancellationToken.Register(static w => ((TaskCompletionSource<PingReply>)w!).TrySetCanceled(), waiter))
                {
                    PingReply reply = await waiter.Task.ConfigureAwait(false);
                    return new PingReply(reply.RemoteAddress, stopwatch.Elapsed, reply.Data);
                }
            }
            finally
            {
                _pings.TryRemove(sequence, out _);
            }
        }

        void SendIp(byte[] ipPacket) => _ = _channel.WriteIpPacketAsync(ipPacket);

        void OnInbound(ReadOnlyMemory<byte> ipPacket)
        {
            if (ipPacket.Length < 20) return;

            // Reassemble fragmented datagrams (RFC 791): whole packets pass through, fragments buffer until complete.
            ReadOnlyMemory<byte>? assembled = _reassembler.Offer(ipPacket);
            if (assembled is null) return;
            ipPacket = assembled.Value;

            ReadOnlySpan<byte> span = ipPacket.Span;
            byte protocol = Ipv4.Protocol(span);
            if (protocol == Ipv4.ProtocolTcp)
            {
                ReadOnlyMemory<byte> tcp = Ipv4.Payload(ipPacket);
                if (tcp.Length < 20) return;
                ushort localPort = TcpSegment.DestinationPort(tcp.Span); // our local port (the segment's destination)
                if (_connections.TryGetValue(localPort, out TcpConnection? connection))
                    connection.OnSegment(tcp);
            }
            else if (protocol == Ipv4.ProtocolUdp)
            {
                ReadOnlyMemory<byte> udp = Ipv4.Payload(ipPacket);
                if (udp.Length < 8) return;
                ushort localPort = UdpDatagram.DestinationPort(udp.Span);
                if (_udpSockets.TryGetValue(localPort, out UdpConnection? socket))
                    socket.OnDatagram(Ipv4.Source(span), UdpDatagram.SourcePort(udp.Span), UdpDatagram.Payload(udp).ToArray());
            }
            else if (protocol == Ipv4.ProtocolIcmp)
            {
                ReadOnlyMemory<byte> icmp = Ipv4.Payload(ipPacket);
                if (icmp.Length < Icmpv4.HeaderSize) return;
                OnIcmp(Ipv4.Source(span), icmp);
            }
        }

        void OnIcmp(IPAddress source, ReadOnlyMemory<byte> icmp)
        {
            ReadOnlySpan<byte> span = icmp.Span;
            switch (Icmpv4.Type(span))
            {
                case Icmpv4.TypeEchoRequest:
                {
                    // Answer pings aimed at this tunnel host: echo the payload back with the same identifier/sequence.
                    byte[] reply = Icmpv4.BuildEcho(Icmpv4.TypeEchoReply, Icmpv4.Identifier(span), Icmpv4.Sequence(span), Icmpv4.Payload(icmp).Span);
                    byte[] ip = Ipv4.Build(_localAddress, source, Ipv4.ProtocolIcmp, reply, (ushort)Interlocked.Increment(ref _icmpIpId));
                    SendIp(ip);
                    break;
                }
                case Icmpv4.TypeEchoReply:
                {
                    if (Icmpv4.Identifier(span) != _pingIdentifier) break;
                    if (_pings.TryGetValue(Icmpv4.Sequence(span), out TaskCompletionSource<PingReply>? waiter))
                        waiter.TrySetResult(new PingReply(source, TimeSpan.Zero, Icmpv4.Payload(icmp).ToArray()));
                    break;
                }
                case Icmpv4.TypeDestinationUnreachable:
                {
                    // The error quotes our offending datagram: original IP header + first 8 bytes (the Echo Request).
                    ReadOnlySpan<byte> quoted = Icmpv4.Payload(icmp).Span;
                    if (quoted.Length < 20) break;
                    int ihl = (quoted[0] & 0x0F) * 4;
                    if (quoted[9] != Ipv4.ProtocolIcmp || quoted.Length < ihl + Icmpv4.HeaderSize) break;
                    ushort id = (ushort)((quoted[ihl + 4] << 8) | quoted[ihl + 5]);
                    if (id != _pingIdentifier) break;
                    ushort sequence = (ushort)((quoted[ihl + 6] << 8) | quoted[ihl + 7]);
                    if (_pings.TryGetValue(sequence, out TaskCompletionSource<PingReply>? waiter))
                        waiter.TrySetException(new IcmpUnreachableException(Icmpv4.Code(span)));
                    break;
                }
            }
        }
    }
}
