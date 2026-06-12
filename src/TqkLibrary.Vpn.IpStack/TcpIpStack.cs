using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.IpStack.Tcp;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;
using TqkLibrary.Vpn.IpStack.Udp;

namespace TqkLibrary.Vpn.IpStack
{
    /// <summary>
    /// Binds an <see cref="IPacketChannel"/> and the local tunnel address(es), demultiplexes inbound TCP/UDP/ICMP
    /// packets to their connections by local port (echo by identifier for ICMP), and actively opens new TCP
    /// connections. Dual-stack: the inbound version nibble selects the IPv4 or IPv6 path, and client-initiated flows
    /// pick their source address from the remote's address family. ICMP is handled per family (ICMPv4 / ICMPv6).
    /// </summary>
    public sealed class TcpIpStack
    {
        static readonly byte[] DefaultPingData = System.Text.Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwabcdefghi");

        readonly IPacketChannel _channel;
        readonly IPAddress? _localV4;
        readonly IPAddress? _localV6;
        readonly ConcurrentDictionary<ushort, TcpConnection> _connections = new();
        readonly ConcurrentDictionary<ushort, UdpConnection> _udpSockets = new();
        readonly ConcurrentDictionary<ushort, TaskCompletionSource<PingReply>> _pings = new();
        readonly Ipv4Reassembler _reassembler = new();
        readonly Ipv6Reassembler _reassemblerV6 = new();
        readonly ushort _pingIdentifier;
        int _nextPort = 49152;
        int _nextPingSequence;
        int _replyIpId;
        int _fragId;

        /// <summary>Creates the stack over the given channel, sourcing packets from a single local address (IPv4 or IPv6).</summary>
        public TcpIpStack(IPacketChannel channel, IPAddress localAddress)
            : this(channel,
                   localAddress.AddressFamily == AddressFamily.InterNetwork ? localAddress : null,
                   localAddress.AddressFamily == AddressFamily.InterNetworkV6 ? localAddress : null)
        {
        }

        /// <summary>
        /// Creates a dual-stack capable stack over the given channel. Provide an IPv4 address, an IPv6 address, or both
        /// (at least one). Inbound packets are demultiplexed by version; outbound flows pick the matching source.
        /// </summary>
        public TcpIpStack(IPacketChannel channel, IPAddress? localV4, IPAddress? localV6)
        {
            if (localV4 is null && localV6 is null)
                throw new ArgumentException("At least one local address (IPv4 or IPv6) is required.");
            if (localV4 is not null && localV4.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("localV4 must be an IPv4 address.", nameof(localV4));
            if (localV6 is not null && localV6.AddressFamily != AddressFamily.InterNetworkV6)
                throw new ArgumentException("localV6 must be an IPv6 address.", nameof(localV6));

            _channel = channel;
            _localV4 = localV4;
            _localV6 = localV6;
            byte[] id = new byte[2];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(id);
            _pingIdentifier = (ushort)((id[0] << 8) | id[1]);
            _channel.InboundIpPacket += OnInbound;
        }

        /// <summary>Opens a TCP connection to <paramref name="remoteAddress"/>:<paramref name="remotePort"/> through the tunnel.</summary>
        public async Task<TcpConnection> ConnectAsync(IPAddress remoteAddress, ushort remotePort, CancellationToken cancellationToken = default)
        {
            ushort localPort = (ushort)Interlocked.Increment(ref _nextPort);
            var connection = new TcpConnection(LocalFor(remoteAddress), localPort, remoteAddress, remotePort, SendIp, linkMtu: _channel.Mtu);
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
            var socket = new UdpConnection(_localV4, _localV6, localPort, SendIp);
            _udpSockets[localPort] = socket;
            return socket;
        }

        /// <summary>
        /// Releases a UDP socket bound by <see cref="BindUdp()"/>: drops it from the demux table so later inbound
        /// datagrams for <paramref name="localPort"/> get an ICMP port-unreachable instead of being queued on a socket
        /// nobody reads. Unlike TCP (auto-removed on close), UDP sockets have no lifecycle, so callers unbind explicitly.
        /// </summary>
        public void UnbindUdp(ushort localPort) => _udpSockets.TryRemove(localPort, out _);

        /// <summary>
        /// Sends an ICMP Echo Request through the tunnel and awaits the matching Echo Reply. Throws
        /// <see cref="IcmpUnreachableException"/> if the target replies Destination Unreachable, or
        /// <see cref="OperationCanceledException"/> if cancelled before a reply arrives. The ICMP version follows
        /// <paramref name="remoteAddress"/>'s address family.
        /// </summary>
        public async Task<PingReply> PingAsync(IPAddress remoteAddress, ReadOnlyMemory<byte> data = default, CancellationToken cancellationToken = default)
        {
            var waiter = new TaskCompletionSource<PingReply>(TaskCreationOptions.RunContinuationsAsynchronously);
            ushort sequence;
            do { sequence = (ushort)Interlocked.Increment(ref _nextPingSequence); } // skip sequences with a ping still
            while (!_pings.TryAdd(sequence, waiter));                               // pending after a 65536-wrap
            try
            {
                ReadOnlySpan<byte> payload = data.IsEmpty ? DefaultPingData : data.Span;
                IPAddress local = LocalFor(remoteAddress);
                byte[] ip;
                if (remoteAddress.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    byte[] icmp = Icmpv6.BuildEcho(Icmpv6.TypeEchoRequest, _pingIdentifier, sequence, payload, local, remoteAddress);
                    ip = IpLayer.Build(local, remoteAddress, Ipv6.NextHeaderIcmpv6, icmp, 0);
                }
                else
                {
                    byte[] icmp = Icmpv4.BuildEcho(Icmpv4.TypeEchoRequest, _pingIdentifier, sequence, payload);
                    ip = IpLayer.Build(local, remoteAddress, Ipv4.ProtocolIcmp, icmp, (ushort)Interlocked.Increment(ref _replyIpId));
                }

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

        IPAddress LocalFor(IPAddress remote)
        {
            IPAddress? local = remote.AddressFamily == AddressFamily.InterNetworkV6 ? _localV6 : _localV4;
            if (local is null)
                throw new InvalidOperationException($"This stack has no local {remote.AddressFamily} address to reach {remote}.");
            return local;
        }

        void SendIp(byte[] ipPacket)
        {
            // Single egress chokepoint: oversized datagrams (large UDP/ICMP) are fragmented to the link MTU (RFC 791 for
            // IPv4, RFC 8200 §4.5 for IPv6) instead of being dropped. TCP segments stay under MSS, so they pass through.
            int mtu = _channel.Mtu;
            if (ipPacket.Length <= mtu)
            {
                _ = _channel.WriteIpPacketAsync(ipPacket);
                return;
            }
            foreach (byte[] fragment in IpLayer.Fragment(ipPacket, mtu, (uint)Interlocked.Increment(ref _fragId)))
                _ = _channel.WriteIpPacketAsync(fragment);
        }

        void OnInbound(ReadOnlyMemory<byte> ipPacket)
        {
            if (ipPacket.Length < 1) return;
            byte version = IpLayer.Version(ipPacket.Span);
            if (version == 4) OnInboundV4(ipPacket);
            else if (version == 6) OnInboundV6(ipPacket);
        }

        void OnInboundV4(ReadOnlyMemory<byte> ipPacket)
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
                else
                    SendTcpReset(Ipv4.Source(span), Ipv4.Destination(span), tcp.Span); // no socket here → RST (RFC 793)
            }
            else if (protocol == Ipv4.ProtocolUdp)
            {
                ReadOnlyMemory<byte> udp = Ipv4.Payload(ipPacket);
                if (udp.Length < 8) return;
                ushort localPort = UdpDatagram.DestinationPort(udp.Span);
                if (_udpSockets.TryGetValue(localPort, out UdpConnection? socket))
                    socket.OnDatagram(Ipv4.Source(span), UdpDatagram.SourcePort(udp.Span), UdpDatagram.Payload(udp).ToArray());
                else
                    SendPortUnreachableV4(span); // no socket here → ICMP port unreachable (RFC 792 / RFC 1122 §3.2.2.1)
            }
            else if (protocol == Ipv4.ProtocolIcmp)
            {
                ReadOnlyMemory<byte> icmp = Ipv4.Payload(ipPacket);
                if (icmp.Length < Icmpv4.HeaderSize) return;
                OnIcmpv4(Ipv4.Source(span), Ipv4.Destination(span), icmp);
            }
        }

        void OnInboundV6(ReadOnlyMemory<byte> ipPacket)
        {
            if (ipPacket.Length < Ipv6.HeaderLength) return;

            // Reassemble Fragment-extension-header datagrams (RFC 8200 §4.5): whole packets pass through.
            ReadOnlyMemory<byte>? assembled = _reassemblerV6.Offer(ipPacket);
            if (assembled is null) return;
            ipPacket = assembled.Value;

            ReadOnlySpan<byte> span = ipPacket.Span;
            if (!Ipv6.TryGetUpperLayer(span, out byte protocol, out int offset)) return;
            IPAddress source = Ipv6.Source(span);
            IPAddress destination = Ipv6.Destination(span);
            ReadOnlyMemory<byte> upper = ipPacket.Slice(offset);

            if (protocol == Ipv6.NextHeaderTcp)
            {
                if (upper.Length < 20) return;
                ushort localPort = TcpSegment.DestinationPort(upper.Span); // our local port (the segment's destination)
                if (_connections.TryGetValue(localPort, out TcpConnection? connection))
                    connection.OnSegment(upper);
                else
                    SendTcpReset(source, destination, upper.Span); // no socket here → RST (RFC 793)
            }
            else if (protocol == Ipv6.NextHeaderUdp)
            {
                if (upper.Length < 8) return;
                ushort localPort = UdpDatagram.DestinationPort(upper.Span);
                if (_udpSockets.TryGetValue(localPort, out UdpConnection? socket))
                    socket.OnDatagram(source, UdpDatagram.SourcePort(upper.Span), UdpDatagram.Payload(upper).ToArray());
                else
                    SendPortUnreachableV6(span); // no socket here → ICMPv6 port unreachable (RFC 4443 §3.1)
            }
            else if (protocol == Ipv6.NextHeaderIcmpv6)
            {
                if (upper.Length < Icmpv6.HeaderSize) return;
                OnIcmpv6(source, destination, upper);
            }
        }

        void OnIcmpv4(IPAddress source, IPAddress destination, ReadOnlyMemory<byte> icmp)
        {
            ReadOnlySpan<byte> span = icmp.Span;
            switch (Icmpv4.Type(span))
            {
                case Icmpv4.TypeEchoRequest:
                {
                    // Answer pings aimed at this tunnel host: reply from our address (the request's destination).
                    byte[] reply = Icmpv4.BuildEcho(Icmpv4.TypeEchoReply, Icmpv4.Identifier(span), Icmpv4.Sequence(span), Icmpv4.Payload(icmp).Span);
                    byte[] ip = Ipv4.Build(destination, source, Ipv4.ProtocolIcmp, reply, (ushort)Interlocked.Increment(ref _replyIpId));
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
                    // The error quotes our offending datagram: original IP header + first 8 bytes.
                    ReadOnlySpan<byte> quoted = Icmpv4.Payload(icmp).Span;
                    if (quoted.Length < 20) break;
                    int ihl = (quoted[0] & 0x0F) * 4;
                    if (quoted[9] == Ipv4.ProtocolTcp && Icmpv4.Code(span) == Icmpv4.CodeFragmentationNeeded)
                    {
                        // Fragmentation-Needed (RFC 1191): the quoted TCP header's first 8 bytes are both ports + the
                        // sequence number — enough to route the Path MTU update to the connection that sent it.
                        if (quoted.Length >= ihl + 8) DeliverPathMtu(quoted, ihl, Icmpv4.NextHopMtu(span));
                        break;
                    }
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

        void OnIcmpv6(IPAddress source, IPAddress destination, ReadOnlyMemory<byte> icmp)
        {
            ReadOnlySpan<byte> span = icmp.Span;
            switch (Icmpv6.Type(span))
            {
                case Icmpv6.TypeEchoRequest:
                {
                    // Answer pings aimed at this tunnel host: reply from our address (the request's destination).
                    byte[] reply = Icmpv6.BuildEcho(Icmpv6.TypeEchoReply, Icmpv6.Identifier(span), Icmpv6.Sequence(span), Icmpv6.Payload(icmp).Span, destination, source);
                    byte[] ip = IpLayer.Build(destination, source, Ipv6.NextHeaderIcmpv6, reply, 0);
                    SendIp(ip);
                    break;
                }
                case Icmpv6.TypeEchoReply:
                {
                    if (Icmpv6.Identifier(span) != _pingIdentifier) break;
                    if (_pings.TryGetValue(Icmpv6.Sequence(span), out TaskCompletionSource<PingReply>? waiter))
                        waiter.TrySetResult(new PingReply(source, TimeSpan.Zero, Icmpv6.Payload(icmp).ToArray()));
                    break;
                }
                case Icmpv6.TypePacketTooBig:
                {
                    // Packet Too Big (RFC 8201) quotes our oversized packet: walk to the embedded TCP segment and route
                    // the Path MTU update to the connection that sent it.
                    ReadOnlySpan<byte> quoted = Icmpv6.Payload(icmp).Span;
                    if (quoted.Length < Ipv6.HeaderLength || IpLayer.Version(quoted) != 6) break;
                    if (!Ipv6.TryGetUpperLayer(quoted, out byte ptbProto, out int ptbOffset)) break;
                    if (ptbProto == Ipv6.NextHeaderTcp && quoted.Length >= ptbOffset + 8)
                        DeliverPathMtu(quoted, ptbOffset, (int)Icmpv6.NextHopMtu(span));
                    break;
                }
                case Icmpv6.TypeDestinationUnreachable:
                {
                    // The error quotes our offending packet (full IPv6 packet up to the min MTU): find the embedded Echo Request.
                    ReadOnlySpan<byte> quoted = Icmpv6.Payload(icmp).Span;
                    if (quoted.Length < Ipv6.HeaderLength || IpLayer.Version(quoted) != 6) break;
                    if (!Ipv6.TryGetUpperLayer(quoted, out byte proto, out int off)) break;
                    if (proto != Ipv6.NextHeaderIcmpv6 || quoted.Length < off + Icmpv6.HeaderSize) break;
                    ReadOnlySpan<byte> embedded = quoted.Slice(off);
                    if (Icmpv6.Type(embedded) != Icmpv6.TypeEchoRequest || Icmpv6.Identifier(embedded) != _pingIdentifier) break;
                    ushort sequence = Icmpv6.Sequence(embedded);
                    if (_pings.TryGetValue(sequence, out TaskCompletionSource<PingReply>? waiter))
                        waiter.TrySetException(new IcmpUnreachableException(Icmpv6.Code(span)));
                    break;
                }
            }
        }

        /// <summary>
        /// Routes a Path MTU Discovery error (ICMPv4 Fragmentation-Needed / ICMPv6 Packet-Too-Big) to the TCP connection
        /// that sent the quoted segment. The quote starts with the offending IP packet; <paramref name="tcpOffset"/> is
        /// where its TCP header begins, whose source port is our local port and whose sequence number identifies the data.
        /// </summary>
        void DeliverPathMtu(ReadOnlySpan<byte> quoted, int tcpOffset, int nextHopMtu)
        {
            ushort localPort = (ushort)((quoted[tcpOffset] << 8) | quoted[tcpOffset + 1]); // our port = quoted segment's source
            uint sequence = ((uint)quoted[tcpOffset + 4] << 24) | ((uint)quoted[tcpOffset + 5] << 16)
                          | ((uint)quoted[tcpOffset + 6] << 8) | quoted[tcpOffset + 7];
            if (_connections.TryGetValue(localPort, out TcpConnection? connection))
                connection.OnIcmpPacketTooBig(nextHopMtu, sequence);
        }

        /// <summary>
        /// Answers an inbound TCP segment aimed at a local port with no connection by sending a RST (RFC 793 p.36):
        /// the peer learns the port is dead instead of retransmitting into the void. A RST is never sent in reply to a
        /// RST, which would otherwise loop into a reset storm. Works for both IPv4 and IPv6 (the addresses carry the family).
        /// </summary>
        void SendTcpReset(IPAddress remote, IPAddress local, ReadOnlySpan<byte> segment)
        {
            TcpFlags flags = TcpSegment.Flags(segment);
            if ((flags & TcpFlags.Rst) != 0) return;

            uint sequence, acknowledgment;
            TcpFlags rstFlags;
            if ((flags & TcpFlags.Ack) != 0)
            {
                // The segment carries an ACK: the RST borrows its sequence and acknowledges nothing of its own.
                sequence = TcpSegment.Acknowledgment(segment);
                acknowledgment = 0;
                rstFlags = TcpFlags.Rst;
            }
            else
            {
                // No ACK to borrow: RST sequence 0, ACK the sequence span the segment consumed (SYN/FIN each count 1).
                int dataLength = Math.Max(0, segment.Length - TcpSegment.DataOffset(segment));
                uint segmentLength = (uint)dataLength
                    + (((flags & TcpFlags.Syn) != 0) ? 1u : 0u)
                    + (((flags & TcpFlags.Fin) != 0) ? 1u : 0u);
                sequence = 0;
                acknowledgment = TcpSegment.Sequence(segment) + segmentLength;
                rstFlags = TcpFlags.Rst | TcpFlags.Ack;
            }

            ushort localPort = TcpSegment.DestinationPort(segment); // our port (the segment's destination)
            ushort remotePort = TcpSegment.SourcePort(segment);
            byte[] reset = TcpSegment.Build(local, remote, localPort, remotePort, sequence, acknowledgment, rstFlags, window: 0, ReadOnlySpan<byte>.Empty);
            SendIp(IpLayer.Build(local, remote, Ipv4.ProtocolTcp, reset, (ushort)Interlocked.Increment(ref _replyIpId)));
        }

        /// <summary>
        /// Answers an inbound IPv4 UDP datagram aimed at a local port with no socket by sending an ICMP Destination
        /// Unreachable / Port Unreachable that quotes the offending datagram (RFC 792, RFC 1122 §3.2.2.1).
        /// </summary>
        void SendPortUnreachableV4(ReadOnlySpan<byte> offendingIpPacket)
        {
            IPAddress remote = Ipv4.Source(offendingIpPacket);
            IPAddress local = Ipv4.Destination(offendingIpPacket);
            byte[] icmp = Icmpv4.BuildDestinationUnreachable(Icmpv4.CodePortUnreachable, offendingIpPacket);
            SendIp(Ipv4.Build(local, remote, Ipv4.ProtocolIcmp, icmp, (ushort)Interlocked.Increment(ref _replyIpId)));
        }

        /// <summary>
        /// Answers an inbound IPv6 UDP datagram aimed at a local port with no socket by sending an ICMPv6 Destination
        /// Unreachable / Port Unreachable that quotes the offending packet (RFC 4443 §3.1).
        /// </summary>
        void SendPortUnreachableV6(ReadOnlySpan<byte> offendingIpPacket)
        {
            IPAddress remote = Ipv6.Source(offendingIpPacket);
            IPAddress local = Ipv6.Destination(offendingIpPacket);
            byte[] icmp = Icmpv6.BuildDestinationUnreachable(Icmpv6.CodePortUnreachable, offendingIpPacket, local, remote);
            SendIp(IpLayer.Build(local, remote, Ipv6.NextHeaderIcmpv6, icmp, 0));
        }
    }
}
