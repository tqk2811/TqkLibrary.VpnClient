using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Ethernet.Enums;
using TqkLibrary.VpnClient.Ethernet.Helpers;
using TqkLibrary.VpnClient.Ethernet.Models;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// The IPv6 implementation of <see cref="IAddressConfigurator"/> — the L2.6 address layer of an
    /// <c>EthernetAdapter</c>, the IPv6 counterpart of <see cref="DhcpV4Configurator"/> (L2.5). It combines two
    /// mechanisms, choosing between them from the Router Advertisement just like a real host:
    /// <list type="bullet">
    /// <item><b>SLAAC</b> (RFC 4862): from a Router Advertisement carrying an autonomous (A) prefix it forms a global
    /// address by combining the /64 prefix with an interface identifier (Modified EUI-64 or a stable opaque one — see
    /// <see cref="SlaacInterfaceIdentifierMode"/>). The advertised router becomes the IPv6 default gateway.</item>
    /// <item><b>Stateful DHCPv6</b> (RFC 8415): when the RA sets the Managed (M) flag (or no usable SLAAC prefix exists,
    /// or <see cref="Ipv6AddressConfiguratorOptions.ForceDhcp"/> is set) it runs SOLICIT → ADVERTISE → REQUEST → REPLY
    /// over UDP 546→547 to the All_DHCP_Relay_Agents_and_Servers multicast <c>ff02::1:2</c> to lease an address; the O
    /// flag additionally pulls DNS from the same exchange.</item>
    /// </list>
    /// The Router Advertisement itself is parsed by <see cref="NdiscResolver"/> (L2.4): this configurator reads
    /// <see cref="NdiscResolver.LastRouterAdvertisement"/> and, if none has arrived, sends a Router Solicitation to elicit
    /// one and waits on <see cref="NdiscResolver.RouterAdvertisementReceived"/>. DHCPv6 replies ride inside ordinary
    /// IPv6, so a composer wires <see cref="HandleInboundFrame"/> to <see cref="VirtualHost.InboundIpPacket"/> (and
    /// <see cref="VirtualHost.InboundNonIpFrame"/> for completeness), exactly as the DHCPv4 client is wired.
    /// </summary>
    public sealed class Ipv6AddressConfigurator : IAddressConfigurator, IAsyncDisposable
    {
        readonly MacAddress _mac;
        readonly IPAddress _linkLocal;
        readonly IEthernetChannel _port;
        readonly NdiscResolver _ndisc;
        readonly Ipv6AddressConfiguratorOptions _options;
        readonly byte[] _clientDuid;
        readonly object _sync = new object();
        TaskCompletionSource<RouterAdvertisementInfo>? _raWaiter;
        uint _dhcpXid;
        TaskCompletionSource<byte[]>? _pendingReply;
        bool _disposed;

        /// <summary>
        /// Creates an IPv6 configurator for the host with MAC <paramref name="mac"/> and link-local address
        /// <paramref name="linkLocal"/>, sending traffic out <paramref name="port"/> (the same switch port its
        /// <see cref="VirtualHost"/> uses) and taking Router Advertisements from <paramref name="ndisc"/> (the L2.4
        /// resolver bound to the same host).
        /// </summary>
        public Ipv6AddressConfigurator(MacAddress mac, IPAddress linkLocal, IEthernetChannel port, NdiscResolver ndisc, Ipv6AddressConfiguratorOptions? options = null)
        {
            if (linkLocal is null)
                throw new ArgumentNullException(nameof(linkLocal));
            if (linkLocal.AddressFamily != AddressFamily.InterNetworkV6)
                throw new ArgumentException("The link-local address must be IPv6.", nameof(linkLocal));
            _mac = mac;
            _linkLocal = linkLocal;
            _port = port ?? throw new ArgumentNullException(nameof(port));
            _ndisc = ndisc ?? throw new ArgumentNullException(nameof(ndisc));
            _options = options ?? Ipv6AddressConfiguratorOptions.Default;
            _clientDuid = Dhcpv6Options.BuildDuidLinkLayer(mac);
            _ndisc.RouterAdvertisementReceived += OnRouterAdvertisement;
        }

        /// <inheritdoc/>
        /// <exception cref="InvalidOperationException">No Router Advertisement arrived, or a forced/managed DHCPv6 exchange produced no address.</exception>
        public async ValueTask<TunnelConfig> ConfigureAsync(CancellationToken cancellationToken = default)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(Ipv6AddressConfigurator));

            RouterAdvertisementInfo ra = await AcquireRouterAdvertisementAsync(cancellationToken).ConfigureAwait(false);

            var config = new TunnelConfig { Mtu = _options.Mtu };
            if (ra.Router != null)
                config.Routes.Add($"::/0 {ra.Router}");   // IPv6 default route via the advertising router

            // SLAAC: form a global address when the RA carries an autonomous /64 prefix (RFC 4862 §5.5.3).
            IPAddress? slaacAddress = TryFormSlaacAddress(ra);
            if (slaacAddress != null)
            {
                config.AssignedAddressV6 = slaacAddress;
                config.PrefixLengthV6 = ra.PrefixLength;
            }

            // Stateful DHCPv6 when the RA asks for it (M flag), when SLAAC produced nothing, or when forced. The O flag
            // (other-config) and a successful lease also bring DNS.
            bool needDhcp = ra.Managed || _options.ForceDhcp || (slaacAddress == null);
            bool wantDhcpDns = needDhcp || ra.OtherConfig;
            if (needDhcp || wantDhcpDns)
            {
                (IPAddress? dhcpAddress, IReadOnlyList<IPAddress> dns) = await RunDhcpv6Async(requireAddress: needDhcp, cancellationToken).ConfigureAwait(false);
                if (dhcpAddress != null && config.AssignedAddressV6 == null)
                {
                    config.AssignedAddressV6 = dhcpAddress;
                    config.PrefixLengthV6 = 128;   // DHCPv6 leases a single address (RFC 8415 §6.5)
                }
                foreach (IPAddress server in dns)
                    config.DnsServers.Add(server);
            }

            if (config.AssignedAddressV6 == null)
                throw new InvalidOperationException("IPv6 autoconfiguration produced no address (no SLAAC prefix and no DHCPv6 lease).");
            return config;
        }

        /// <summary>
        /// Returns the most recent Router Advertisement, soliciting one (Router Solicitation to ff02::2) and waiting if
        /// none has been seen yet — retried up to <see cref="Ipv6AddressConfiguratorOptions.RouterSolicitationAttempts"/>.
        /// </summary>
        async Task<RouterAdvertisementInfo> AcquireRouterAdvertisementAsync(CancellationToken cancellationToken)
        {
            RouterAdvertisementInfo? cached = _ndisc.LastRouterAdvertisement;
            if (cached != null)
                return cached;

            for (int attempt = 0; attempt < _options.RouterSolicitationAttempts; attempt++)
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(Ipv6AddressConfigurator));

                var waiter = new TaskCompletionSource<RouterAdvertisementInfo>(TaskCreationOptions.RunContinuationsAsynchronously);
                lock (_sync)
                {
                    if (_disposed)
                        throw new ObjectDisposedException(nameof(Ipv6AddressConfigurator));
                    // A Router Advertisement may already have raced in before we registered the waiter.
                    RouterAdvertisementInfo? now = _ndisc.LastRouterAdvertisement;
                    if (now != null)
                        return now;
                    _raWaiter = waiter;
                }

                await SendRouterSolicitationAsync(cancellationToken).ConfigureAwait(false);

                RouterAdvertisementInfo? ra = await AwaitAsync(waiter.Task, _options.RouterAdvertisementTimeout, cancellationToken).ConfigureAwait(false);
                lock (_sync)
                {
                    if (ReferenceEquals(_raWaiter, waiter))
                        _raWaiter = null;
                }
                if (ra != null)
                    return ra;
            }
            throw new InvalidOperationException($"No Router Advertisement within {_options.RouterSolicitationAttempts} Router Solicitation(s).");
        }

        IPAddress? TryFormSlaacAddress(RouterAdvertisementInfo ra)
        {
            if (ra.Prefix == null || !ra.PrefixAutonomous || ra.PrefixLength != 64 || ra.PrefixValidLifetime == 0)
                return null;   // no autonomous /64 prefix with a non-zero lifetime → SLAAC forms nothing

            byte[] iid = _options.InterfaceIdentifierMode == SlaacInterfaceIdentifierMode.StableOpaque
                ? SlaacAddress.StableInterfaceIdentifier(ra.Prefix, _mac)
                : SlaacAddress.ModifiedEui64(_mac);
            return SlaacAddress.Combine(ra.Prefix, ra.PrefixLength, iid);
        }

        /// <summary>
        /// Runs the stateful DHCPv6 four-message exchange (RFC 8415 §18.2): SOLICIT → ADVERTISE → REQUEST → REPLY. The
        /// transaction id is shared across the two requests. Returns the leased address (or <c>null</c>) and DNS list.
        /// </summary>
        async Task<(IPAddress? address, IReadOnlyList<IPAddress> dns)> RunDhcpv6Async(bool requireAddress, CancellationToken cancellationToken)
        {
            uint xid = NewTransactionId();
            const uint iaid = 1;   // a single Identity Association is enough for one address

            byte[] advertise = await ExchangeAsync(BuildSolicit(xid, iaid), xid, Dhcpv6Packet.MessageAdvertise, cancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte> advOptions = Dhcpv6Packet.OptionField(advertise);
            if (!Dhcpv6Options.TryGetOption(advOptions.Span, Dhcpv6Options.CodeServerId, out ReadOnlySpan<byte> serverIdSpan))
                throw new InvalidOperationException("DHCPv6 ADVERTISE carried no Server Identifier.");
            byte[] serverId = serverIdSpan.ToArray();
            IPAddress? offered = Dhcpv6Options.ReadAssignedAddress(advOptions.Span, out _, out _);

            byte[] reply = await ExchangeAsync(BuildRequest(xid, iaid, serverId, offered), xid, Dhcpv6Packet.MessageReply, cancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte> replyOptions = Dhcpv6Packet.OptionField(reply);

            ushort status = Dhcpv6Options.ReadStatusCode(replyOptions.Span);
            if (status != Dhcpv6Options.StatusSuccess && requireAddress)
                throw new InvalidOperationException($"DHCPv6 REPLY status code {status} (not success).");

            IPAddress? leased = Dhcpv6Options.ReadAssignedAddress(replyOptions.Span, out _, out _);
            if (leased == null && requireAddress)
                throw new InvalidOperationException("DHCPv6 REPLY assigned no address.");
            return (leased, Dhcpv6Options.ReadDnsServers(replyOptions.Span));
        }

        /// <summary>
        /// Sends <paramref name="request"/> and awaits a reply of <paramref name="expectedType"/> for transaction
        /// <paramref name="xid"/>, retransmitting on timeout up to <see cref="Ipv6AddressConfiguratorOptions.DhcpMaxAttempts"/>.
        /// </summary>
        async Task<byte[]> ExchangeAsync(byte[] request, uint xid, byte expectedType, CancellationToken cancellationToken)
        {
            for (int attempt = 0; attempt < _options.DhcpMaxAttempts; attempt++)
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(Ipv6AddressConfigurator));

                var reply = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                lock (_sync)
                {
                    if (_disposed)
                        throw new ObjectDisposedException(nameof(Ipv6AddressConfigurator));
                    _dhcpXid = xid;
                    _pendingReply = reply;
                }

                await _port.WriteFrameAsync(MulticastFrame(request), cancellationToken).ConfigureAwait(false);

                byte[]? message = await AwaitAsync(reply.Task, _options.DhcpReplyTimeout, cancellationToken).ConfigureAwait(false);
                lock (_sync)
                {
                    if (ReferenceEquals(_pendingReply, reply))
                        _pendingReply = null;
                }
                if (message == null)
                    continue;   // timed out: retransmit
                if (Dhcpv6Packet.MessageType(message) == expectedType)
                    return message;
                // Any other message type for our xid keeps the attempt waiting via the retransmit loop.
            }
            throw new InvalidOperationException($"DHCPv6 did not receive the expected reply (type {expectedType}) within {_options.DhcpMaxAttempts} attempt(s).");
        }

        /// <summary>
        /// Feeds one inbound frame to the configurator (wired to <see cref="VirtualHost.InboundIpPacket"/> and
        /// <see cref="VirtualHost.InboundNonIpFrame"/>): if it carries a UDP/IPv6 DHCPv6 reply (port 547 → 546) whose
        /// transaction id matches the in-flight exchange, it completes the pending wait. (Router Advertisements are
        /// handled by <see cref="NdiscResolver"/>, not here.)
        /// </summary>
        public void HandleInboundFrame(ReadOnlyMemory<byte> frame)
        {
            if (_disposed)
                return;

            // Accept either a full Ethernet frame (InboundNonIpFrame) or a bare IPv6 packet (InboundIpPacket).
            ReadOnlyMemory<byte> ipPacket;
            if (frame.Length >= EthernetFrame.HeaderLength && EthernetFrame.EtherType(frame.Span) == EthernetFrame.EtherTypeIpv6)
                ipPacket = EthernetFrame.Payload(frame);
            else
                ipPacket = frame;

            if (!Dhcpv6Packet.TryReadUdpIpv6(ipPacket, out ReadOnlyMemory<byte> dhcpMessage))
                return;

            TaskCompletionSource<byte[]>? toComplete = null;
            byte[]? message = null;
            lock (_sync)
            {
                if (_disposed || _pendingReply == null)
                    return;
                if (Dhcpv6Packet.TransactionId(dhcpMessage.Span) != _dhcpXid)
                    return;
                toComplete = _pendingReply;
                message = dhcpMessage.ToArray();
                _pendingReply = null;
            }
            toComplete.TrySetResult(message!);   // completed outside any caller's continuation (RunContinuationsAsynchronously)
        }

        void OnRouterAdvertisement(RouterAdvertisementInfo info)
        {
            TaskCompletionSource<RouterAdvertisementInfo>? waiter;
            lock (_sync)
            {
                waiter = _raWaiter;
                _raWaiter = null;
            }
            waiter?.TrySetResult(info);
        }

        ValueTask SendRouterSolicitationAsync(CancellationToken cancellationToken)
        {
            byte[] rs = Icmpv6Ndisc.BuildRouterSolicitation(_linkLocal, Icmpv6Ndisc.AllRouters, _mac);
            byte[] ipv6 = Icmpv6Ndisc.BuildIpv6(_linkLocal, Icmpv6Ndisc.AllRouters, rs);
            MacAddress dst = Icmpv6Ndisc.MulticastMac(Icmpv6Ndisc.AllRouters);   // 33:33 + last 4 bytes of ff02::2
            byte[] frame = EthernetFrame.Build(dst, _mac, EthernetFrame.EtherTypeIpv6, ipv6);
            return _port.WriteFrameAsync(frame, cancellationToken);
        }

        byte[] BuildSolicit(uint xid, uint iaid)
        {
            byte[] iaNa = Dhcpv6Options.BuildIaNa(iaid, t1: 0, t2: 0, ReadOnlySpan<byte>.Empty);
            byte[] options = new byte[256];
            int pos = WriteCommonOptions(options, 0);
            pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeIaNa, iaNa);
            return Dhcpv6Packet.Build(Dhcpv6Packet.MessageSolicit, xid, options.AsSpan(0, pos));
        }

        byte[] BuildRequest(uint xid, uint iaid, byte[] serverId, IPAddress? offered)
        {
            // Echo the offered address back inside the IA_NA so the server confirms exactly what it advertised.
            byte[] iaNa = offered != null
                ? Dhcpv6Options.BuildIaNa(iaid, t1: 0, t2: 0, Dhcpv6Options.BuildIaAddressOption(offered, 0, 0))
                : Dhcpv6Options.BuildIaNa(iaid, t1: 0, t2: 0, ReadOnlySpan<byte>.Empty);
            byte[] options = new byte[256 + serverId.Length];
            int pos = WriteCommonOptions(options, 0);
            pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeServerId, serverId);
            pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeIaNa, iaNa);
            return Dhcpv6Packet.Build(Dhcpv6Packet.MessageRequest, xid, options.AsSpan(0, pos));
        }

        /// <summary>Writes the options every client message carries: Client-ID (our DUID), Elapsed-Time, Option-Request.</summary>
        int WriteCommonOptions(byte[] options, int pos)
        {
            pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeClientId, _clientDuid);
            byte[] elapsed = { 0x00, 0x00 };   // first message of the exchange (RFC 8415 §21.9)
            pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeElapsedTime, elapsed);
            byte[] oro = Dhcpv6Options.BuildOptionRequest(Dhcpv6Options.CodeDnsServers);
            pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeOptionRequest, oro);
            return pos;
        }

        byte[] MulticastFrame(byte[] dhcpMessage)
        {
            byte[] udpIp = Dhcpv6Packet.BuildUdpIpv6(_linkLocal, Dhcpv6Packet.AllRelayAgentsAndServers,
                Dhcpv6Packet.ClientPort, Dhcpv6Packet.ServerPort, dhcpMessage);
            MacAddress dst = Icmpv6Ndisc.MulticastMac(Dhcpv6Packet.AllRelayAgentsAndServers);   // 33:33:00:01:00:02
            return EthernetFrame.Build(dst, _mac, EthernetFrame.EtherTypeIpv6, udpIp);
        }

        uint NewTransactionId()
        {
            Span<byte> b = stackalloc byte[3];
#if NET6_0_OR_GREATER
            System.Security.Cryptography.RandomNumberGenerator.Fill(b);
#else
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                byte[] tmp = new byte[3];
                rng.GetBytes(tmp);
                tmp.CopyTo(b);
            }
#endif
            return ((uint)b[0] << 16) | ((uint)b[1] << 8) | b[2];   // 24-bit DHCPv6 transaction id
        }

        /// <summary>Awaits <paramref name="task"/> but gives up after <paramref name="timeout"/> (returns <c>null</c>).</summary>
        static async Task<T?> AwaitAsync<T>(Task<T> task, TimeSpan timeout, CancellationToken cancellationToken) where T : class
        {
            if (task.IsCompleted)
                return await task.ConfigureAwait(false);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            Task delay = Task.Delay(timeout, timeoutCts.Token);
            Task winner = await Task.WhenAny(task, delay).ConfigureAwait(false);
            if (winner == task)
            {
                timeoutCts.Cancel();   // release the pending delay timer
                return await task.ConfigureAwait(false);
            }
            cancellationToken.ThrowIfCancellationRequested();   // delay fired due to cancellation, not a timeout
            return null;
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            TaskCompletionSource<byte[]>? pending;
            TaskCompletionSource<RouterAdvertisementInfo>? raWaiter;
            lock (_sync)
            {
                if (_disposed)
                    return default;
                _disposed = true;
                pending = _pendingReply;
                _pendingReply = null;
                raWaiter = _raWaiter;
                _raWaiter = null;
            }
            _ndisc.RouterAdvertisementReceived -= OnRouterAdvertisement;
            pending?.TrySetCanceled();     // release any in-flight DHCPv6 exchange
            raWaiter?.TrySetCanceled();    // release any in-flight RA wait
            return default;
        }
    }
}
