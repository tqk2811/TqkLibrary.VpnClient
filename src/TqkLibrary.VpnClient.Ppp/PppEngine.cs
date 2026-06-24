using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Ppp.Enums;
using TqkLibrary.VpnClient.Ppp.Framing.Enums;
using TqkLibrary.VpnClient.Ppp.Interfaces;

namespace TqkLibrary.VpnClient.Ppp
{
    /// <summary>
    /// Drives a PPP session over an <see cref="IPppFrameChannel"/>: runs LCP, an optional authentication phase
    /// (e.g. MS-CHAPv2 over CHAP), then IPCP; demultiplexes inbound frames by protocol field and exposes an
    /// <see cref="IPacketChannel"/> once the link is up.
    /// </summary>
    public sealed class PppEngine : IDisposable
    {
        readonly IPppFrameChannel _channel;
        readonly LcpNegotiator _lcp;
        readonly IpcpNegotiator _ipcp;
        readonly Ipv6cpNegotiator? _ipv6cp;
        readonly PppPacketChannel _packetChannel;
        readonly IPppAuthenticator? _authenticator;
        readonly ILogger _logger;
        readonly object _sync = new();
        readonly bool _deferNetworkLayer;

        const string Layer = "ppp";
        bool _networkLayerStarted;
        bool _readyForNetworkLayer; // LCP up + auth done; waiting only on the deferral gate (CCP/MPPE)
        bool _gateReleased;         // the caller opened CCP/MPPE (StartNetworkLayer); releases the deferral
        bool _disposed;

        /// <summary>
        /// Creates an engine. <paramref name="localAddress"/> is the IP we request (0.0.0.0 for a client).
        /// Pass <paramref name="assignPeerAddress"/> to act as the server. Pass <paramref name="authenticator"/>
        /// to satisfy a server that demands authentication. Set <paramref name="enableIpv6"/> to also run IPV6CP
        /// (RFC 5072) alongside IPCP: it negotiates an Interface-Identifier → link-local fe80::/64 address without
        /// affecting the IPv4 link-up (IPCP stays the trigger for <see cref="LinkUp"/>). <paramref name="interfaceId"/>
        /// is the 8-byte identifier we request (default: derived from <paramref name="magic"/>);
        /// <paramref name="assignPeerInterfaceId"/> forces one onto the peer when acting as a server.
        /// <para>
        /// <paramref name="deferNetworkLayer"/> holds IPCP/IPV6CP back even after LCP + auth complete, until the
        /// caller invokes <see cref="StartNetworkLayer"/>. PPTP needs this: once CCP negotiates MPPE, every non-LCP
        /// packet (IPCP included) must be MPPE-encrypted, so the network layer must not start until CCP/MPPE is open —
        /// otherwise the first IPCP Configure-Request goes out in the clear and the peer Protocol-Rejects it (and the
        /// stray cleartext packet can desync the peer's MPPE state). L2TP/SSTP leave this false (no CCP).
        /// </para>
        /// <para><paramref name="logger"/> receives the LCP/IPCP/IPV6CP/auth protocol traces; null logs to a no-op
        /// logger (no behaviour change).</para>
        /// </summary>
        public PppEngine(
            IPppFrameChannel channel,
            uint magic,
            IPAddress localAddress,
            IPAddress? assignPeerAddress = null,
            IPAddress? assignPeerDns = null,
            IPppAuthenticator? authenticator = null,
            int mtu = 1400,
            bool enableIpv6 = false,
            byte[]? interfaceId = null,
            byte[]? assignPeerInterfaceId = null,
            bool deferNetworkLayer = false,
            ILogger? logger = null)
        {
            _channel = channel;
            _channel.FrameReceived += OnFrame;
            _authenticator = authenticator;
            _deferNetworkLayer = deferNetworkLayer;
            _logger = logger ?? NullLogger.Instance;
            _lcp = new LcpNegotiator(p => SendControl(PppProtocol.Lcp, p), magic, _logger);
            _ipcp = new IpcpNegotiator(p => SendControl(PppProtocol.Ipcp, p), localAddress, assignPeerAddress, assignPeerDns, _logger);
            _packetChannel = new PppPacketChannel(SendIpAsync, mtu);
            _lcp.Opened += OnLcpOpened;
            _ipcp.Opened += OnIpcpOpened;
            if (enableIpv6)
            {
                _ipv6cp = new Ipv6cpNegotiator(p => SendControl(PppProtocol.Ipv6cp, p), interfaceId ?? DeriveInterfaceId(magic), assignPeerInterfaceId, _logger);
                _ipv6cp.Opened += OnIpv6cpOpened;
            }
        }

        /// <summary>Raised once IPCP is open and the link can carry IPv4 traffic.</summary>
        public event Action? LinkUp;

        /// <summary>Raised once IPV6CP is open and a link-local IPv6 address has been negotiated (only when IPv6 is enabled).</summary>
        public event Action? Ipv6Up;

        /// <summary>Raised when authentication succeeds.</summary>
        public event Action? AuthSucceeded;

        /// <summary>Raised when authentication fails.</summary>
        public event Action? AuthFailed;

        /// <summary>The L3 channel for this session (valid after <see cref="LinkUp"/>).</summary>
        public IPacketChannel PacketChannel => _packetChannel;

        /// <summary>Our negotiated IP address.</summary>
        public IPAddress AssignedAddress => _ipcp.AssignedAddress;

        /// <summary>DNS server learned via IPCP, if any.</summary>
        public IPAddress? AssignedDns => _ipcp.AssignedDns;

        /// <summary>Our negotiated link-local IPv6 address (fe80::/64 + Interface-Identifier), or null if IPv6 is not enabled.</summary>
        public IPAddress? AssignedAddressV6 => _ipv6cp?.LinkLocalAddress;

        /// <summary>True once the link is up (IPCP opened).</summary>
        public bool IsLinkUp { get; private set; }

        /// <summary>True once IPV6CP has opened and a link-local IPv6 address is available.</summary>
        public bool IsIpv6Up { get; private set; }

        /// <summary>True once authentication has succeeded (or none was required).</summary>
        public bool IsAuthenticated { get; private set; }

        /// <summary>Begins negotiation (LCP first).</summary>
        public void Start()
        {
            lock (_sync) _lcp.Start();
        }

        void OnLcpOpened()
        {
            if (_lcp.RequiresMsChapV2 && _authenticator != null)
                return; // wait for the server's CHAP Challenge; the network layer starts after auth succeeds.

            IsAuthenticated = true; // no auth required
            ReadyForNetworkLayer();
        }

        /// <summary>
        /// Releases a deferred network layer (PPTP after CCP/MPPE opens). When <c>deferNetworkLayer</c> was set, the
        /// engine reaches the ready state (LCP + auth done) but holds IPCP/IPV6CP back until this is called; calling it
        /// before the engine is ready arms the start so it fires the moment auth completes. No-op when not deferred or
        /// already started. Invoked under the engine lock so it composes with frame handling.
        /// </summary>
        public void StartNetworkLayer()
        {
            lock (_sync)
            {
                if (_disposed || _networkLayerStarted) return;
                _gateReleased = true;
                if (_readyForNetworkLayer) StartNetworkLayerLocked();
            }
        }

        // LCP is up and auth (if any) succeeded: start the network layer now, or wait for the deferral gate to release.
        void ReadyForNetworkLayer()
        {
            _readyForNetworkLayer = true;
            if (_deferNetworkLayer && !_gateReleased) return; // hold IPCP until the caller opens CCP/MPPE
            StartNetworkLayerLocked();
        }

        // Starts the network-control protocols once the link (and any auth + deferral gate) is up: IPCP always, IPV6CP when enabled.
        void StartNetworkLayerLocked()
        {
            if (_networkLayerStarted) return;
            _networkLayerStarted = true;
            _ipcp.Start();
            _ipv6cp?.Start();
        }

        void OnIpcpOpened()
        {
            IsLinkUp = true;
            _logger.LogProtocolStep(Layer, "IPCP opened — link up (IPv4)");
            LinkUp?.Invoke();
        }

        void OnIpv6cpOpened()
        {
            IsIpv6Up = true;
            _logger.LogProtocolStep(Layer, "IPV6CP opened — link-local IPv6 negotiated");
            Ipv6Up?.Invoke();
        }

        void HandleAuth(ReadOnlySpan<byte> packet)
        {
            PppAuthStatus status = _authenticator!.Handle(packet, out byte[]? response);
            if (response != null)
                SendControl(PppProtocol.Chap, response);

            switch (status)
            {
                case PppAuthStatus.Success:
                    IsAuthenticated = true;
                    _logger.LogProtocolStep(Layer, "authentication succeeded");
                    AuthSucceeded?.Invoke();   // PPTP hooks this to start CCP; the network layer then waits for the gate
                    ReadyForNetworkLayer();
                    break;
                case PppAuthStatus.Failure:
                    _logger.LogProtocolStep(Layer, "authentication failed");
                    AuthFailed?.Invoke();
                    break;
            }
        }

        void OnFrame(ReadOnlyMemory<byte> frame)
        {
            ReadOnlySpan<byte> span = frame.Span;
            int offset = 0;
            if (span.Length >= 2 && span[0] == 0xFF && span[1] == 0x03) offset = 2; // skip Address/Control
            if (span.Length < offset + 2) return;

            ushort proto = (ushort)((span[offset] << 8) | span[offset + 1]);
            ReadOnlyMemory<byte> info = frame.Slice(offset + 2);
            lock (_sync)
            {
                switch ((PppProtocol)proto)
                {
                    case PppProtocol.Lcp: _lcp.HandlePacket(info.Span); break;
                    case PppProtocol.Chap:
                        if (_authenticator != null) HandleAuth(info.Span);
                        break;
                    case PppProtocol.Ipcp: _ipcp.HandlePacket(info.Span); break;
                    case PppProtocol.Ipv6cp: _ipv6cp?.HandlePacket(info.Span); break;
                    case PppProtocol.Ip:
                    case PppProtocol.Ipv6: _packetChannel.RaiseInbound(info); break; // one L3 channel carries both families
                }
            }
        }

        void SendControl(PppProtocol proto, byte[] payload) => _ = _channel.SendAsync(BuildFrame((ushort)proto, payload));

        // Frame an outbound IP packet with the matching PPP protocol: 0x0021 for IPv4, 0x0057 for IPv6 (chosen by the
        // version nibble). The stack hands us raw IP packets of either family on one channel; PPP carries them apart.
        ValueTask SendIpAsync(ReadOnlyMemory<byte> ipPacket)
        {
            ReadOnlySpan<byte> span = ipPacket.Span;
            PppProtocol proto = span.Length > 0 && (span[0] >> 4) == 6 ? PppProtocol.Ipv6 : PppProtocol.Ip;
            return _channel.SendAsync(BuildFrame((ushort)proto, span));
        }

        // A deterministic, non-zero, locally-administered 8-byte Interface-Identifier derived from the PPP magic
        // number (EUI-64 layout with the fffe fill). Servers usually Nak it with their own value anyway.
        static byte[] DeriveInterfaceId(uint magic) => new byte[]
        {
            0x02,                                                        // U/L bit set (locally administered), unicast
            (byte)(magic >> 24), (byte)(magic >> 16), (byte)(magic >> 8),
            0xFF, 0xFE,                                                  // EUI-64 fill
            (byte)magic, 0x01,                                          // non-zero tail
        };

        static byte[] BuildFrame(ushort proto, ReadOnlySpan<byte> payload)
        {
            byte[] frame = new byte[4 + payload.Length];
            frame[0] = 0xFF;
            frame[1] = 0x03;
            frame[2] = (byte)(proto >> 8);
            frame[3] = (byte)proto;
            payload.CopyTo(frame.AsSpan(4));
            return frame;
        }

        /// <summary>
        /// Detaches from the frame channel and stops every negotiator's Restart timer. Call this when the attempt is
        /// torn down (drop/reconnect/teardown) so a half-finished negotiation's timer cannot keep retransmitting onto a
        /// disposed channel. Safe to call more than once.
        /// </summary>
        public void Dispose()
        {
            lock (_sync)
            {
                if (_disposed) return;
                _disposed = true;
            }
            _channel.FrameReceived -= OnFrame;
            _lcp.Dispose();
            _ipcp.Dispose();
            _ipv6cp?.Dispose();
        }
    }
}
