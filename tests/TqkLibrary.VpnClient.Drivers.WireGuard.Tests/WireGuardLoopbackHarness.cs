using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.WireGuard.Transport;
using TqkLibrary.VpnClient.WireGuard;
using TqkLibrary.VpnClient.WireGuard.DataChannel;
using TqkLibrary.VpnClient.WireGuard.Handshake;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;

namespace TqkLibrary.VpnClient.Drivers.WireGuard.Tests
{
    /// <summary>
    /// Offline harness for driving the real <see cref="WireGuardConnection"/> against an in-process WireGuard responder
    /// built from the same protocol blocks (<see cref="WireGuardHandshake"/> responder path + <see cref="WireGuardTransport"/>).
    /// A lossless ordered in-memory UDP loopback ties the two together. This is throwaway test scaffolding: the library
    /// is a client, the responder role exists only here.
    /// </summary>
    sealed class LoopbackUdpLink
    {
        readonly Endpoint _client = new();
        readonly Endpoint _server = new();

        public LoopbackUdpLink() { _client.Peer = _server; _server.Peer = _client; }

        /// <summary>The client's UDP pipe (the connection's transport).</summary>
        public Endpoint Client => _client;

        /// <summary>The server's UDP pipe (the responder's transport).</summary>
        public Endpoint Server => _server;

        /// <summary>An in-memory connected datagram pipe; each send is delivered to the peer in order on the thread pool.</summary>
        public sealed class Endpoint : IDatagramTransport
        {
            public Endpoint? Peer;
            readonly object _lock = new();
            Task _tail = Task.CompletedTask;
            Action<ReadOnlyMemory<byte>>? _receiver;

            /// <summary>Registers the inbound handler (the driver's demux, or the responder's loop).</summary>
            public void SetReceiver(Action<ReadOnlyMemory<byte>> receiver) => _receiver = receiver;

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
            {
                byte[] copy = datagram.ToArray();
                Endpoint? peer = Peer;
                if (peer != null)
                    lock (peer._lock)
                        peer._tail = peer._tail.ContinueWith(_ => peer._receiver?.Invoke(copy), TaskScheduler.Default);
                return default;
            }

            public ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
                => throw new NotSupportedException("The loopback link self-pumps via the registered receiver.");

            public ValueTask DisposeAsync() => default;
        }
    }

    /// <summary>An <see cref="IWireGuardTransportFactory"/> that hands back a fixed in-process pipe (self-pumping loopback).</summary>
    sealed class InProcessWireGuardTransportFactory : IWireGuardTransportFactory
    {
        readonly LoopbackUdpLink.Endpoint _endpoint;
        public InProcessWireGuardTransportFactory(LoopbackUdpLink.Endpoint endpoint) => _endpoint = endpoint;

        public Task<WireGuardTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
            => Task.FromResult(new WireGuardTransportHandle(_endpoint, _endpoint.SetReceiver, receivePump: null));
    }

    /// <summary>
    /// An <see cref="IWireGuardTransportFactory"/> that returns a <b>different</b> in-process pipe per requested
    /// endpoint (the connection asks for one transport per distinct peer endpoint). It is the offline stand-in for N
    /// real UDP sockets: each endpoint gets its own loopback, so a test can prove a peer's outbound went to its own
    /// endpoint. Records every endpoint it was asked to connect, and reuses one pipe per endpoint (value equality on
    /// IP + port), mirroring the connection's own de-dup.
    /// </summary>
    sealed class EndpointRoutingWireGuardTransportFactory : IWireGuardTransportFactory
    {
        readonly IReadOnlyDictionary<IPEndPoint, LoopbackUdpLink.Endpoint> _byEndpoint;
        readonly List<IPEndPoint> _connected = new();

        public EndpointRoutingWireGuardTransportFactory(IReadOnlyDictionary<IPEndPoint, LoopbackUdpLink.Endpoint> byEndpoint)
            => _byEndpoint = byEndpoint;

        /// <summary>The endpoints the connection asked for a transport to, in order (one entry per distinct endpoint).</summary>
        public IReadOnlyList<IPEndPoint> ConnectedEndpoints => _connected;

        public Task<WireGuardTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
        {
            _connected.Add(remote);
            if (!_byEndpoint.TryGetValue(remote, out LoopbackUdpLink.Endpoint? endpoint))
                throw new InvalidOperationException($"No loopback wired for endpoint {remote} (the test must register every peer's endpoint).");
            return Task.FromResult(new WireGuardTransportHandle(endpoint, endpoint.SetReceiver, receivePump: null));
        }
    }

    /// <summary>
    /// A throwaway WireGuard responder: it answers a type-1 initiation with a type-2 response (running the responder
    /// half of <see cref="WireGuardHandshake"/>), derives the transport keys, then opens inbound type-4 datagrams and
    /// echoes each non-empty inner packet straight back. Optionally it can answer the <i>first</i> initiation with a
    /// cookie-reply to exercise the mac2 path. The loopback is lossless and ordered, so no retransmit/reorder logic.
    /// </summary>
    sealed class SimulatedWireGuardResponder : IDisposable
    {
        readonly LoopbackUdpLink.Endpoint _transport;
        readonly WireGuardKeyPair _static;
        readonly byte[]? _psk;
        readonly byte[]? _peerStaticPublic;
        readonly WireGuardMessageCodec _codec = new();
        readonly object _sync = new();
        readonly byte[] _cookieSecret;
        readonly byte[] _sourceAddress;

        WireGuardTransport? _data;
        uint _localIndex;
        uint _peerIndex;
        int _initiationsSeen;
        readonly bool _cookieOnFirst;

        /// <summary>Count of inbound type-4 data packets the responder opened (test assertion hook).</summary>
        public int DataPacketsOpened { get; private set; }

        public SimulatedWireGuardResponder(LoopbackUdpLink.Endpoint transport, WireGuardKeyPair staticKey,
            byte[]? peerStaticPublic = null, byte[]? psk = null, bool cookieOnFirstInitiation = false)
        {
            _transport = transport;
            _static = staticKey;
            _psk = psk;
            _peerStaticPublic = peerStaticPublic;
            _cookieOnFirst = cookieOnFirstInitiation;
            _cookieSecret = new byte[32];
            for (int i = 0; i < _cookieSecret.Length; i++) _cookieSecret[i] = (byte)(0xC0 + i);
            _sourceAddress = new byte[] { 10, 0, 0, 9, 0x4F, 0x21 }; // a stable fake UDP source (IP+port)
            _transport.SetReceiver(OnInbound);
        }

        void OnInbound(ReadOnlyMemory<byte> datagram)
        {
            ReadOnlySpan<byte> span = datagram.Span;
            if (span.Length < 1) return;
            byte type = span[0];
            if (type == WireGuardConstants.MessageTypeInitiation) HandleInitiation(span);
            else if (type == WireGuardConstants.MessageTypeTransportData) HandleData(span);
        }

        void HandleInitiation(ReadOnlySpan<byte> span)
        {
            if (!_codec.TryDecodeInitiation(span, out WireGuardInitiationMessage init)) return;

            var handshake = new WireGuardHandshake(_static, remoteStaticPublic: _peerStaticPublic, presharedKey: _psk);
            if (!handshake.VerifyIncomingMac1(span)) return; // forged — drop

            bool first;
            lock (_sync) { first = _initiationsSeen == 0; _initiationsSeen++; }

            // Under "load" on the first initiation, answer with a cookie-reply instead of doing the DH (DoS path).
            if (_cookieOnFirst && first)
            {
                WireGuardCookieReplyMessage reply = handshake.CreateCookieReply(
                    init.SenderIndex, span, _cookieSecret, _sourceAddress);
                _ = _transport.SendAsync(_codec.EncodeCookieReply(reply));
                return;
            }

            if (!handshake.ConsumeInitiation(init, out _, out _)) return;

            uint localIndex = first ? 0xA1B2C3D4u : 0xA1B2C3D5u;
            WireGuardResponseMessage resp = handshake.CreateResponse(localIndex, init.SenderIndex);
            byte[] wire = _codec.EncodeResponse(resp);
            handshake.StampOutgoingMacs(wire);

            WireGuardTransportKeys keys = handshake.DeriveTransportKeys();
            lock (_sync)
            {
                _localIndex = localIndex;
                _peerIndex = init.SenderIndex;
                _data = new WireGuardTransport(keys, sendReceiverIndex: init.SenderIndex, localReceiverIndex: localIndex);
            }
            _ = _transport.SendAsync(wire);
        }

        void HandleData(ReadOnlySpan<byte> span)
        {
            WireGuardTransport? data;
            lock (_sync) data = _data;
            if (data is null) return;
            if (!data.TryOpen(span, out byte[] inner)) return;
            DataPacketsOpened++;
            if (inner.Length == 0) return; // keepalive — do not echo
            _ = _transport.SendAsync(data.Seal(inner)); // echo the inner packet back
        }

        /// <summary>Test stimulus: the responder sends an unsolicited inner packet to the client.</summary>
        public void SendToClient(byte[] inner)
        {
            WireGuardTransport? data;
            lock (_sync) data = _data;
            if (data != null) _ = _transport.SendAsync(data.Seal(inner));
        }

        public void Dispose() { }
    }

    /// <summary>Mints standalone X25519 static identities for the harness (independent of any live handshake).</summary>
    static class WireGuardTestKeys
    {
        public static WireGuardKeyPair NewStatic() => new WireGuardHandshake(
            new WireGuardKeyPair { PrivateKey = new byte[32], PublicKey = new byte[32] }).GenerateKeyPair();
    }
}
