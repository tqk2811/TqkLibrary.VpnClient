using System.Net;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.Ppp.Enums;
using TqkLibrary.Vpn.Ppp.Framing.Enums;
using TqkLibrary.Vpn.Ppp.Interfaces;

namespace TqkLibrary.Vpn.Ppp
{
    /// <summary>
    /// Drives a PPP session over an <see cref="IPppFrameChannel"/>: runs LCP, an optional authentication phase
    /// (e.g. MS-CHAPv2 over CHAP), then IPCP; demultiplexes inbound frames by protocol field and exposes an
    /// <see cref="IPacketChannel"/> once the link is up.
    /// </summary>
    public sealed class PppEngine
    {
        readonly IPppFrameChannel _channel;
        readonly LcpNegotiator _lcp;
        readonly IpcpNegotiator _ipcp;
        readonly PppPacketChannel _packetChannel;
        readonly IPppAuthenticator? _authenticator;
        readonly object _sync = new();

        /// <summary>
        /// Creates an engine. <paramref name="localAddress"/> is the IP we request (0.0.0.0 for a client).
        /// Pass <paramref name="assignPeerAddress"/> to act as the server. Pass <paramref name="authenticator"/>
        /// to satisfy a server that demands authentication.
        /// </summary>
        public PppEngine(
            IPppFrameChannel channel,
            uint magic,
            IPAddress localAddress,
            IPAddress? assignPeerAddress = null,
            IPAddress? assignPeerDns = null,
            IPppAuthenticator? authenticator = null,
            int mtu = 1400)
        {
            _channel = channel;
            _channel.FrameReceived += OnFrame;
            _authenticator = authenticator;
            _lcp = new LcpNegotiator(p => SendControl(PppProtocol.Lcp, p), magic);
            _ipcp = new IpcpNegotiator(p => SendControl(PppProtocol.Ipcp, p), localAddress, assignPeerAddress, assignPeerDns);
            _packetChannel = new PppPacketChannel(SendIpAsync, mtu);
            _lcp.Opened += OnLcpOpened;
            _ipcp.Opened += OnIpcpOpened;
        }

        /// <summary>Raised once IPCP is open and the link can carry IP traffic.</summary>
        public event Action? LinkUp;

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

        /// <summary>True once the link is up (IPCP opened).</summary>
        public bool IsLinkUp { get; private set; }

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
                return; // wait for the server's CHAP Challenge; IPCP starts after auth succeeds.

            IsAuthenticated = true; // no auth required
            _ipcp.Start();
        }

        void OnIpcpOpened()
        {
            IsLinkUp = true;
            LinkUp?.Invoke();
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
                    AuthSucceeded?.Invoke();
                    _ipcp.Start();
                    break;
                case PppAuthStatus.Failure:
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
                    case PppProtocol.Ip: _packetChannel.RaiseInbound(info); break;
                }
            }
        }

        void SendControl(PppProtocol proto, byte[] payload) => _ = _channel.SendAsync(BuildFrame((ushort)proto, payload));

        ValueTask SendIpAsync(ReadOnlyMemory<byte> ipPacket) => _channel.SendAsync(BuildFrame((ushort)PppProtocol.Ip, ipPacket.Span));

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
    }
}
