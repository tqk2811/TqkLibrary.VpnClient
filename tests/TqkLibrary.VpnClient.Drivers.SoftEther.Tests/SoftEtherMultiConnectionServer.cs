using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.SoftEther.Transport;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.SoftEther;
using TqkLibrary.VpnClient.SoftEther.DataChannel;
using TqkLibrary.VpnClient.SoftEther.DataChannel.Enums;

namespace TqkLibrary.VpnClient.Drivers.SoftEther.Tests
{
    /// <summary>
    /// A throwaway multi-connection SoftEther server (SecureNAT) for the offline driver tests. The first connection runs
    /// the control handshake and is answered with a <c>welcome</c> that grants <see cref="MaxConnection"/> parallel
    /// connections (and the <see cref="HalfConnection"/> flag); each later connection is an <c>additional_connect</c>
    /// that reattaches by the session key. One shared data session then reads blocks off <b>every</b> attached
    /// connection (each its own decode loop) and replies — DHCP OFFER/ACK, ARP, and IPv4 echo — by spreading frames
    /// round-robin across the send-capable connections, exactly mirroring the client's multi-connection model. This is
    /// test scaffolding only (the library is a client; there is no server product).
    /// </summary>
    sealed class SoftEtherMultiConnectionServer
    {
        readonly IPAddress _leasedAddress = IPAddress.Parse("192.168.30.10");
        readonly IPAddress _gateway = IPAddress.Parse("192.168.30.1");
        readonly IPAddress _subnetMask = IPAddress.Parse("255.255.255.0");
        readonly IPAddress _dns = IPAddress.Parse("192.168.30.1");
        readonly MacAddress _gatewayMac = MacAddress.Parse("5e:00:00:00:00:01");
        readonly byte[] _serverRandom = Enumerable.Range(0, SoftEtherProtocol.RandomSize).Select(i => (byte)(0x10 + i)).ToArray();
        readonly byte[] _sessionKey = Enumerable.Range(0, 20).Select(i => (byte)(0xA0 + i)).ToArray();

        readonly uint _grantedMaxConnection;
        readonly bool _halfConnection;

        // The connections attached to this one logical session, in attach order (primary first), with their direction.
        readonly List<(DuplexPipe pipe, SoftEtherConnectionDirection direction)> _data = new();
        readonly object _sendLock = new();
        int _sendCursor = -1;

        MacAddress _clientMac;
        int _dhcpReplies;
        int _attached;

        public SoftEtherMultiConnectionServer(uint grantedMaxConnection, bool halfConnection = false)
        {
            _grantedMaxConnection = grantedMaxConnection;
            _halfConnection = halfConnection;
        }

        public IPAddress LeasedAddress => _leasedAddress;
        public MacAddress GatewayMac => _gatewayMac;
        public int DhcpReplies => Volatile.Read(ref _dhcpReplies);
        public int AttachedConnections => Volatile.Read(ref _attached);

        /// <summary>
        /// Accepts a freshly-connected client pipe. The first call runs the login handshake (and starts the shared data
        /// session once all expected connections have attached); later calls are <c>additional_connect</c> attaches.
        /// Returns a task that runs that connection's data-read loop for the session's lifetime.
        /// </summary>
        public async Task AcceptAsync(DuplexPipe pipe, bool isPrimary, CancellationToken cancellationToken)
        {
            SoftEtherConnectionDirection direction;
            try
            {
                // Read the request (login / additional_connect), register the connection in the shared session, THEN
                // send the reply — so by the time the client's handshake await returns the server already routes data
                // here (no startup race for the DHCP reply, which in half-duplex must go out a specific connection).
                if (isPrimary) await ReadLoginAsync(pipe, cancellationToken).ConfigureAwait(false);
                else await ReadAdditionalConnectAsync(pipe, cancellationToken).ConfigureAwait(false);

                int index = Interlocked.Increment(ref _attached) - 1;
                direction = SoftEtherConnectionDirectionAt(index);
                lock (_data)
                    _data.Add((pipe, direction));

                if (isPrimary) await SendWelcomeAsync(pipe).ConfigureAwait(false);
                else await SendAdditionalConnectAckAsync(pipe).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (SoftEtherProtocolException) { return; }

            await RunDataReadLoopAsync(pipe, direction, cancellationToken).ConfigureAwait(false);
        }

        // Mirror the client's planner so a Send-only client connection is a Receive-only server connection and vice versa.
        SoftEtherConnectionDirection SoftEtherConnectionDirectionAt(int index)
        {
            // The total expected count is min(client desired, granted); the test always opens exactly granted here, so
            // mirror the planner over the granted count.
            var clientDirections = SoftEtherConnectionDirectionPlanner.Plan((int)_grantedMaxConnection, _halfConnection);
            var clientDir = clientDirections[Math.Min(index, clientDirections.Length - 1)];
            return clientDir switch
            {
                SoftEtherConnectionDirection.Send => SoftEtherConnectionDirection.Receive,
                SoftEtherConnectionDirection.Receive => SoftEtherConnectionDirection.Send,
                _ => SoftEtherConnectionDirection.Both,
            };
        }

        // ---- control handshakes ----

        async Task ReadLoginAsync(DuplexPipe pipe, CancellationToken cancellationToken)
        {
            await ReadWatermarkAndReplyHelloAsync(pipe, cancellationToken).ConfigureAwait(false);
            (_, byte[] loginBody) = await ReadHttpMessageAsync(pipe, cancellationToken).ConfigureAwait(false);
            Pack login = SoftEtherHttpPackCodec.ParseBody(loginBody);
            _ = login.GetStr("username");
        }

        async Task SendWelcomeAsync(DuplexPipe pipe)
        {
            var welcome = new Pack().SetInt("error", 0u).SetData("session_name", _sessionKey)
                .SetInt("max_connection", _grantedMaxConnection)
                .SetBool("half_connection", _halfConnection);
            await pipe.WriteAsync(SoftEtherHttpPackCodec.BuildOkResponse(welcome)).ConfigureAwait(false);
        }

        async Task ReadAdditionalConnectAsync(DuplexPipe pipe, CancellationToken cancellationToken)
        {
            await ReadWatermarkAndReplyHelloAsync(pipe, cancellationToken).ConfigureAwait(false);
            (_, byte[] body) = await ReadHttpMessageAsync(pipe, cancellationToken).ConfigureAwait(false);
            Pack pack = SoftEtherHttpPackCodec.ParseBody(body);
            if (pack.GetStr("method") != "additional_connect")
                throw new SoftEtherProtocolException("server: expected additional_connect.");
            byte[]? key = pack.GetData("session_name");
            if (key is null || !key.SequenceEqual(_sessionKey))
                throw new SoftEtherProtocolException("server: rejected additional_connect (unknown session key).");
        }

        async Task SendAdditionalConnectAckAsync(DuplexPipe pipe)
            => await pipe.WriteAsync(SoftEtherHttpPackCodec.BuildOkResponse(new Pack().SetInt("error", 0u))).ConfigureAwait(false);

        async Task ReadWatermarkAndReplyHelloAsync(DuplexPipe pipe, CancellationToken cancellationToken)
        {
            (string head, _) = await ReadHttpMessageAsync(pipe, cancellationToken).ConfigureAwait(false);
            if (!head.StartsWith("POST /vpnsvc/connect.cgi", StringComparison.Ordinal))
                throw new SoftEtherProtocolException("server: unexpected watermark target.");
            var hello = new Pack().SetStr("hello", "softether").SetInt("version", 441u).SetInt("build", 9772u)
                .SetData("random", _serverRandom);
            await pipe.WriteAsync(SoftEtherHttpPackCodec.BuildOkResponse(hello)).ConfigureAwait(false);
        }

        // ---- shared data session: one read loop per connection, replies spread round-robin across send connections ----

        async Task RunDataReadLoopAsync(DuplexPipe pipe, SoftEtherConnectionDirection direction, CancellationToken cancellationToken)
        {
            // A Send-only (server side) connection carries server→client only — no inbound to read.
            if (direction == SoftEtherConnectionDirection.Send) return;

            var reader = new SoftEtherDataBlockReader(pipe);
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    IReadOnlyList<byte[]> frames = await reader.ReadBlockAsync(cancellationToken).ConfigureAwait(false);
                    if (frames.Count == 0) return;   // client closed this connection
                    foreach (byte[] frame in frames)
                        await HandleFrameAsync(frame, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
            catch (SoftEtherProtocolException) { }
        }

        async Task HandleFrameAsync(byte[] frame, CancellationToken cancellationToken)
        {
            if (SoftEtherDataFrameCodec.IsKeepAlive(frame)) return;
            if (frame.Length < EthernetFrame.HeaderLength) return;
            byte[]? reply = BuildReply(frame);
            if (reply != null) await SendFrameAsync(reply, cancellationToken).ConfigureAwait(false);
        }

        byte[]? BuildReply(byte[] frame)
        {
            ushort etherType = EthernetFrame.EtherType(frame);
            _clientMac = EthernetFrame.Source(frame);
            if (etherType == EthernetFrame.EtherTypeArp) return BuildArpReply(frame);
            if (etherType == EthernetFrame.EtherTypeIpv4)
            {
                ReadOnlyMemory<byte> ip = EthernetFrame.Payload(frame);
                if (TryReadDhcpRequest(ip, out ReadOnlyMemory<byte> dhcp)) return BuildDhcpReplyFrame(dhcp);
                return BuildIpEcho(frame);
            }
            return null;
        }

        // Spread server→client frames round-robin across the connections that carry that direction (Both or, in
        // half-duplex, the Send-only server side). Pinned under a lock so the cursor + writes stay consistent.
        ValueTask SendFrameAsync(byte[] frame, CancellationToken cancellationToken)
        {
            DuplexPipe target;
            lock (_sendLock)
            {
                var sendable = _data.Where(d => d.direction != SoftEtherConnectionDirection.Receive).ToList();
                if (sendable.Count == 0) return default;
                int next = (int)((uint)(++_sendCursor) % (uint)sendable.Count);
                target = sendable[next].pipe;
            }
            return target.WriteAsync(SoftEtherDataFrameCodec.EncodeSingle(frame), cancellationToken);
        }

        byte[]? BuildArpReply(byte[] frame)
        {
            ReadOnlySpan<byte> arp = EthernetFrame.Payload(frame).Span;
            if (!ArpPacket.IsIpv4OverEthernet(arp) || ArpPacket.Operation(arp) != ArpPacket.OperationRequest) return null;
            MacAddress senderMac = ArpPacket.SenderMac(arp);
            IPAddress senderIp = ArpPacket.SenderIp(arp);
            IPAddress targetIp = ArpPacket.TargetIp(arp);
            return EthernetFrame.Build(senderMac, _gatewayMac, EthernetFrame.EtherTypeArp,
                ArpPacket.BuildReply(_gatewayMac, targetIp, senderMac, senderIp));
        }

        static bool TryReadDhcpRequest(ReadOnlyMemory<byte> packet, out ReadOnlyMemory<byte> dhcpMessage)
        {
            dhcpMessage = default;
            ReadOnlySpan<byte> span = packet.Span;
            if (span.Length < 28 || (byte)(span[0] >> 4) != 4) return false;
            int ihl = (span[0] & 0x0F) * 4;
            if (ihl < 20 || span.Length < ihl + 8 || span[9] != 17) return false;
            int udp = ihl;
            int destPort = (span[udp + 2] << 8) | span[udp + 3];
            if (destPort != DhcpV4Packet.ServerPort) return false;
            int udpLength = (span[udp + 4] << 8) | span[udp + 5];
            if (udpLength < 8 || udp + udpLength > span.Length) return false;
            dhcpMessage = packet.Slice(udp + 8, udpLength - 8);
            return true;
        }

        byte[]? BuildDhcpReplyFrame(ReadOnlyMemory<byte> dhcp)
        {
            byte type = DhcpV4Options.ReadMessageType(DhcpV4Packet.OptionField(dhcp).Span);
            byte replyType =
                type == DhcpV4Options.MessageDiscover ? DhcpV4Options.MessageOffer :
                type == DhcpV4Options.MessageRequest ? DhcpV4Options.MessageAck : (byte)0;
            if (replyType == 0) return null;
            uint xid = DhcpV4Packet.Xid(dhcp.Span);
            Interlocked.Increment(ref _dhcpReplies);
            return BuildDhcpReply(xid, replyType);
        }

        byte[] BuildDhcpReply(uint xid, byte messageType)
        {
            var opt = new byte[128];
            int pos = DhcpV4Options.WriteMagicCookie(opt, 0);
            pos = DhcpV4Options.WriteOption(opt, pos, DhcpV4Options.CodeMessageType, messageType);
            pos = DhcpV4Options.WriteOption(opt, pos, DhcpV4Options.CodeServerId, _gateway);
            pos = DhcpV4Options.WriteOption(opt, pos, DhcpV4Options.CodeSubnetMask, _subnetMask);
            pos = DhcpV4Options.WriteOption(opt, pos, DhcpV4Options.CodeRouter, _gateway);
            pos = DhcpV4Options.WriteOption(opt, pos, DhcpV4Options.CodeDnsServer, _dns);
            pos = DhcpV4Options.WriteOption(opt, pos, DhcpV4Options.CodeLeaseTime, new byte[] { 0, 0, 0x0E, 0x10 });
            pos = DhcpV4Options.WriteEnd(opt, pos);

            byte[] message = BuildBootReply(xid, _leasedAddress, _gateway, _clientMac, opt.AsSpan(0, pos));
            byte[] udpIp = DhcpV4Packet.BuildUdpIpv4(_gateway, IPAddress.Broadcast,
                DhcpV4Packet.ServerPort, DhcpV4Packet.ClientPort, message);
            return EthernetFrame.Build(_clientMac, _gatewayMac, EthernetFrame.EtherTypeIpv4, udpIp);
        }

        static byte[] BuildBootReply(uint xid, IPAddress yiaddr, IPAddress siaddr, MacAddress clientMac, ReadOnlySpan<byte> options)
        {
            byte[] message = new byte[DhcpV4Packet.HeaderLength + options.Length];
            message[0] = DhcpV4Packet.OpBootReply;
            message[1] = DhcpV4Packet.HardwareTypeEthernet;
            message[2] = DhcpV4Packet.HardwareAddressLength;
            message[4] = (byte)(xid >> 24); message[5] = (byte)(xid >> 16); message[6] = (byte)(xid >> 8); message[7] = (byte)xid;
            yiaddr.GetAddressBytes().CopyTo(message, 16);
            siaddr.GetAddressBytes().CopyTo(message, 20);
            clientMac.CopyTo(message.AsSpan(28, MacAddress.Size));
            options.CopyTo(message.AsSpan(DhcpV4Packet.HeaderLength));
            return message;
        }

        byte[] BuildIpEcho(byte[] frame)
        {
            MacAddress src = EthernetFrame.Source(frame);
            ReadOnlyMemory<byte> ip = EthernetFrame.Payload(frame);
            return EthernetFrame.Build(src, _gatewayMac, EthernetFrame.EtherTypeIpv4, ip.Span);
        }

        // ---- minimal HTTP reader (mirrors the single-connection harness) ----

        static async Task<(string head, byte[] body)> ReadHttpMessageAsync(DuplexPipe pipe, CancellationToken cancellationToken)
        {
            var buffer = new List<byte>();
            int headerEnd = -1;
            var chunk = new byte[1024];
            while (headerEnd < 0)
            {
                int n = await pipe.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
                if (n == 0) throw new SoftEtherProtocolException("server: stream closed before headers.");
                for (int i = 0; i < n; i++) buffer.Add(chunk[i]);
                headerEnd = FindHeaderEnd(buffer);
            }
            string head = Encoding.ASCII.GetString(buffer.ToArray(), 0, headerEnd);
            int contentLength = ParseContentLength(head);
            int bodyStart = headerEnd + 4;
            var body = new byte[contentLength];
            int have = Math.Min(contentLength, buffer.Count - bodyStart);
            for (int i = 0; i < have; i++) body[i] = buffer[bodyStart + i];
            int filled = have;
            while (filled < contentLength)
            {
                int n = await pipe.ReadAsync(new Memory<byte>(body, filled, contentLength - filled), cancellationToken).ConfigureAwait(false);
                if (n == 0) throw new SoftEtherProtocolException("server: stream closed before body.");
                filled += n;
            }
            return (head, body);
        }

        static int FindHeaderEnd(List<byte> buffer)
        {
            for (int i = 0; i + 3 < buffer.Count; i++)
                if (buffer[i] == '\r' && buffer[i + 1] == '\n' && buffer[i + 2] == '\r' && buffer[i + 3] == '\n')
                    return i;
            return -1;
        }

        static int ParseContentLength(string head)
        {
            foreach (string line in head.Split(new[] { "\r\n" }, StringSplitOptions.None))
            {
                int c = line.IndexOf(':');
                if (c < 0) continue;
                if (line.Substring(0, c).Trim().Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                    return int.Parse(line.Substring(c + 1).Trim());
            }
            throw new SoftEtherProtocolException("server: no Content-Length.");
        }
    }

    /// <summary>
    /// An <see cref="ISoftEtherTransportFactory"/> that creates a fresh in-memory pipe per connect and hands the server
    /// end to a <see cref="SoftEtherMultiConnectionServer"/> (the first connect being the primary login, the rest
    /// <c>additional_connect</c>). Lets the real driver open its multi-connection session against the offline server.
    /// </summary>
    sealed class MultiConnectionTransportFactory : ISoftEtherTransportFactory
    {
        readonly SoftEtherMultiConnectionServer _server;
        readonly CancellationToken _serverToken;
        readonly ConcurrentBag<Task> _serverTasks = new();
        int _connectIndex = -1;

        public MultiConnectionTransportFactory(SoftEtherMultiConnectionServer server, CancellationToken serverToken)
        {
            _server = server;
            _serverToken = serverToken;
        }

        public ValueTask<IByteStreamTransport> ConnectAsync(string host, int port,
            AddressFamilyPreference addressFamilyPreference, CancellationToken cancellationToken)
        {
            var (client, server) = DuplexPipe.CreatePair();
            bool isPrimary = Interlocked.Increment(ref _connectIndex) == 0;
            _serverTasks.Add(Task.Run(() => _server.AcceptAsync(server, isPrimary, _serverToken)));
            return new ValueTask<IByteStreamTransport>(client);
        }
    }
}
