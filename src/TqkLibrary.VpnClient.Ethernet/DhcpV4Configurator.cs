using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// The DHCPv4 client implementation of <see cref="IAddressConfigurator"/> (RFC 2131) — the L2.5 address layer of an
    /// <c>EthernetAdapter</c>, the IPv4 lease counterpart of <see cref="ArpResolver"/>'s neighbor resolution. It owns one
    /// host's MAC and shares that host's switch port (<see cref="IEthernetChannel"/>) for sending DHCP traffic; inbound
    /// frames carrying a DHCP reply are fed in through <see cref="HandleInboundFrame"/>, which a composer wires to
    /// <see cref="VirtualHost.InboundIpPacket"/> (DHCP rides inside ordinary IPv4 broadcast, so the stack would otherwise
    /// swallow it) and to <see cref="VirtualHost.InboundNonIpFrame"/> for completeness. It depends only on the Ethernet
    /// codec + <see cref="IEthernetChannel"/>, never on <see cref="VirtualHost"/>, so the two can be constructed without
    /// a cycle.
    /// <para>
    /// <see cref="ConfigureAsync"/> runs the four-way handshake: broadcast a DISCOVER (option 53 = 1) and await an OFFER
    /// (53 = 2), broadcast a REQUEST (53 = 3, echoing the offered address in option 50 and the server in option 54) and
    /// await an ACK (53 = 5). It then builds a <see cref="TunnelConfig"/> from yiaddr (address), the subnet mask
    /// (option 1 → prefix length), the router (option 3 → default-route), and DNS servers (option 6). A NAK (53 = 6)
    /// restarts the handshake; running out of attempts fails.
    /// </para>
    /// This client serves IPv4 only (RFC 2131); IPv6 stateless/stateful configuration is SLAAC/DHCPv6 (L2.6).
    /// </summary>
    public sealed class DhcpV4Configurator : IAddressConfigurator, IAsyncDisposable
    {
        static readonly IPAddress Unspecified = IPAddress.Any;             // 0.0.0.0
        static readonly IPAddress LimitedBroadcast = IPAddress.Broadcast;  // 255.255.255.255

        readonly MacAddress _mac;
        readonly IEthernetChannel _port;
        readonly DhcpV4ConfiguratorOptions _options;
        readonly object _sync = new object();
        uint _xid;
        TaskCompletionSource<byte[]>? _pendingReply;
        bool _disposed;

        /// <summary>
        /// Creates a DHCPv4 client for the host with MAC <paramref name="mac"/>, sending DHCP traffic out
        /// <paramref name="port"/> (the same switch port its <see cref="VirtualHost"/> uses).
        /// </summary>
        public DhcpV4Configurator(MacAddress mac, IEthernetChannel port, DhcpV4ConfiguratorOptions? options = null)
        {
            _mac = mac;
            _port = port ?? throw new ArgumentNullException(nameof(port));
            _options = options ?? DhcpV4ConfiguratorOptions.Default;
        }

        /// <inheritdoc/>
        /// <exception cref="InvalidOperationException">No OFFER/ACK arrived within the configured attempts, or the server NAK'd repeatedly.</exception>
        public async ValueTask<TunnelConfig> ConfigureAsync(CancellationToken cancellationToken = default)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(DhcpV4Configurator));

            // A fresh transaction id per attempt cycle correlates our request with the server's reply (RFC 2131 §3).
            uint xid = NewTransactionId();

            byte[] offer = await ExchangeAsync(BuildDiscover(xid), xid, DhcpV4Options.MessageOffer, cancellationToken).ConfigureAwait(false);
            IPAddress offered = DhcpV4Packet.YourIpAddress(offer);
            ReadOnlySpan<byte> offerOptions = DhcpV4Packet.OptionField(offer).Span;
            IPAddress serverId = DhcpV4Options.ReadAddress(offerOptions, DhcpV4Options.CodeServerId)
                                 ?? DhcpV4Packet.ServerIpAddress(offer);

            byte[] ack = await ExchangeAsync(BuildRequest(xid, offered, serverId), xid, DhcpV4Options.MessageAck, cancellationToken).ConfigureAwait(false);
            return BuildTunnelConfig(ack);
        }

        /// <summary>
        /// Sends <paramref name="request"/> and awaits a reply of <paramref name="expectedType"/> for transaction
        /// <paramref name="xid"/>, retransmitting on timeout up to <see cref="DhcpV4ConfiguratorOptions.MaxAttempts"/>.
        /// A NAK aborts the exchange (the caller restarts); running out of attempts throws.
        /// </summary>
        async Task<byte[]> ExchangeAsync(byte[] request, uint xid, byte expectedType, CancellationToken cancellationToken)
        {
            for (int attempt = 0; attempt < _options.MaxAttempts; attempt++)
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(DhcpV4Configurator));

                var reply = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                lock (_sync)
                {
                    if (_disposed)
                        throw new ObjectDisposedException(nameof(DhcpV4Configurator));
                    _xid = xid;
                    _pendingReply = reply;
                }

                await _port.WriteFrameAsync(BroadcastFrame(request), cancellationToken).ConfigureAwait(false);

                byte[]? message = await AwaitReplyAsync(reply.Task, _options.ReplyTimeout, cancellationToken).ConfigureAwait(false);
                lock (_sync)
                {
                    if (ReferenceEquals(_pendingReply, reply))
                        _pendingReply = null;
                }
                if (message == null)
                    continue;   // timed out: retransmit

                byte type = DhcpV4Options.ReadMessageType(DhcpV4Packet.OptionField(message).Span);
                if (type == DhcpV4Options.MessageNak)
                    throw new InvalidOperationException("DHCP server replied NAK to the address request.");
                if (type == expectedType)
                    return message;
                // Any other message type for our xid is ignored; keep waiting within this attempt's budget by retrying.
            }
            throw new InvalidOperationException($"DHCP did not receive the expected reply (type {expectedType}) within {_options.MaxAttempts} attempt(s).");
        }

        /// <summary>
        /// Feeds one inbound frame to the DHCP client (wired to <see cref="VirtualHost.InboundIpPacket"/> and
        /// <see cref="VirtualHost.InboundNonIpFrame"/>): if it carries a UDP/IPv4 DHCP reply (port 67 → 68) whose xid
        /// matches the in-flight exchange, it completes the pending wait.
        /// </summary>
        public void HandleInboundFrame(ReadOnlyMemory<byte> frame)
        {
            if (_disposed)
                return;

            // Accept either a full Ethernet frame (InboundNonIpFrame) or a bare IPv4 packet (InboundIpPacket).
            ReadOnlyMemory<byte> ipPacket;
            if (frame.Length >= EthernetFrame.HeaderLength && EthernetFrame.EtherType(frame.Span) == EthernetFrame.EtherTypeIpv4)
                ipPacket = EthernetFrame.Payload(frame);
            else
                ipPacket = frame;

            if (!DhcpV4Packet.TryReadUdpIpv4(ipPacket, out ReadOnlyMemory<byte> dhcpMessage))
                return;

            TaskCompletionSource<byte[]>? toComplete = null;
            byte[]? message = null;
            lock (_sync)
            {
                if (_disposed || _pendingReply == null)
                    return;
                if (!DhcpV4Packet.IsReplyFor(dhcpMessage.Span, _xid))
                    return;
                toComplete = _pendingReply;
                message = dhcpMessage.ToArray();
                _pendingReply = null;
            }
            toComplete.TrySetResult(message!);   // completed outside any caller's continuation (RunContinuationsAsynchronously)
        }

        byte[] BuildDiscover(uint xid)
        {
            byte[] options = new byte[64];
            int pos = DhcpV4Options.WriteMagicCookie(options, 0);
            pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeMessageType, DhcpV4Options.MessageDiscover);
            pos = WriteClientId(options, pos);
            pos = WriteParameterRequestList(options, pos);
            pos = DhcpV4Options.WriteEnd(options, pos);
            return DhcpV4Packet.Build(xid, _mac, requestedCiaddr: null, broadcast: true, options.AsSpan(0, pos));
        }

        byte[] BuildRequest(uint xid, IPAddress requestedAddress, IPAddress serverId)
        {
            byte[] options = new byte[80];
            int pos = DhcpV4Options.WriteMagicCookie(options, 0);
            pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeMessageType, DhcpV4Options.MessageRequest);
            pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeRequestedIp, requestedAddress);
            pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeServerId, serverId);
            pos = WriteClientId(options, pos);
            pos = WriteParameterRequestList(options, pos);
            pos = DhcpV4Options.WriteEnd(options, pos);
            // ciaddr stays 0.0.0.0 in the SELECTING→REQUESTING state (RFC 2131 §4.3.2): the address is in option 50.
            return DhcpV4Packet.Build(xid, _mac, requestedCiaddr: null, broadcast: true, options.AsSpan(0, pos));
        }

        int WriteClientId(byte[] options, int pos)
        {
            // Client Identifier (option 61): type 1 (Ethernet) + the 6-byte MAC (RFC 2132 §9.14).
            Span<byte> clientId = stackalloc byte[1 + MacAddress.Size];
            clientId[0] = DhcpV4Packet.HardwareTypeEthernet;
            _mac.CopyTo(clientId.Slice(1));
            return DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeClientId, clientId);
        }

        static int WriteParameterRequestList(byte[] options, int pos)
        {
            // The options we want the server to send back (RFC 2132 §9.8).
            Span<byte> requested = stackalloc byte[3];
            requested[0] = DhcpV4Options.CodeSubnetMask;   // 1
            requested[1] = DhcpV4Options.CodeRouter;       // 3
            requested[2] = DhcpV4Options.CodeDnsServer;    // 6
            return DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeParameterRequestList, requested);
        }

        byte[] BroadcastFrame(byte[] dhcpMessage)
        {
            byte[] udpIp = DhcpV4Packet.BuildUdpIpv4(Unspecified, LimitedBroadcast, DhcpV4Packet.ClientPort, DhcpV4Packet.ServerPort, dhcpMessage);
            return EthernetFrame.Build(MacAddress.Broadcast, _mac, EthernetFrame.EtherTypeIpv4, udpIp);
        }

        TunnelConfig BuildTunnelConfig(byte[] ack)
        {
            ReadOnlySpan<byte> options = DhcpV4Packet.OptionField(ack).Span;
            var config = new TunnelConfig
            {
                AssignedAddress = DhcpV4Packet.YourIpAddress(ack),
                Mtu = _options.Mtu,
            };

            IPAddress? mask = DhcpV4Options.ReadAddress(options, DhcpV4Options.CodeSubnetMask);
            config.PrefixLength = mask != null ? MaskToPrefix(mask) : 32;

            IReadOnlyList<IPAddress> routers = DhcpV4Options.ReadAddresses(options, DhcpV4Options.CodeRouter);
            if (routers.Count > 0)
            {
                config.Gateway = routers[0];                    // the next hop for anything off this subnet
                config.Routes.Add($"0.0.0.0/0 {routers[0]}");   // default route via the first advertised gateway
            }

            foreach (IPAddress dns in DhcpV4Options.ReadAddresses(options, DhcpV4Options.CodeDnsServer))
                config.DnsServers.Add(dns);

            return config;
        }

        /// <summary>Counts the leading one-bits of an IPv4 subnet mask → CIDR prefix length (e.g. 255.255.255.0 → 24).</summary>
        public static int MaskToPrefix(IPAddress mask)
        {
            int bits = 0;
            foreach (byte b in mask.GetAddressBytes())
            {
                byte v = b;
                while ((v & 0x80) != 0) { bits++; v <<= 1; }
                if (v != 0) break;   // stop at the first zero bit (a contiguous mask)
            }
            return bits;
        }

        uint NewTransactionId()
        {
            Span<byte> b = stackalloc byte[4];
#if NET6_0_OR_GREATER
            System.Security.Cryptography.RandomNumberGenerator.Fill(b);
#else
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                byte[] tmp = new byte[4];
                rng.GetBytes(tmp);
                tmp.CopyTo(b);
            }
#endif
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        /// <summary>Awaits <paramref name="replyTask"/> but gives up after <paramref name="timeout"/> (returns <c>null</c>).</summary>
        static async Task<byte[]?> AwaitReplyAsync(Task<byte[]> replyTask, TimeSpan timeout, CancellationToken cancellationToken)
        {
            if (replyTask.IsCompleted)
                return await replyTask.ConfigureAwait(false);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            Task delay = Task.Delay(timeout, timeoutCts.Token);
            Task winner = await Task.WhenAny(replyTask, delay).ConfigureAwait(false);
            if (winner == replyTask)
            {
                timeoutCts.Cancel();   // release the pending delay timer
                return await replyTask.ConfigureAwait(false);
            }
            cancellationToken.ThrowIfCancellationRequested();   // delay fired due to cancellation, not a timeout
            return null;
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            TaskCompletionSource<byte[]>? pending;
            lock (_sync)
            {
                if (_disposed)
                    return default;
                _disposed = true;
                pending = _pendingReply;
                _pendingReply = null;
            }
            pending?.TrySetCanceled();   // release any in-flight exchange
            return default;
        }
    }
}
