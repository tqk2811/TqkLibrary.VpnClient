using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Diagnostics.Extensions;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.Ssh.Config;
using TqkLibrary.VpnClient.Drivers.Ssh.DataChannel;
using TqkLibrary.VpnClient.Drivers.Ssh.Transport;
using TqkLibrary.VpnClient.Ssh;

namespace TqkLibrary.VpnClient.Drivers.Ssh
{
    /// <summary>
    /// A complete VPN-over-SSH client to a single OpenSSH server. It opens one TCP connection, runs the SSH-2 transport
    /// handshake (<see cref="SshClient.ConnectAsync"/>: version exchange → curve25519-sha256 KEX → ed25519 host-key verify
    /// → chacha20-poly1305@openssh.com / aes256-gcm@openssh.com → publickey/password auth → <c>tun@openssh.com</c>
    /// point-to-point channel), then carries bare IP packets behind a stable
    /// <see cref="Abstractions.Channels.SwappablePacketChannel"/>: outbound packets go to <see cref="SshClient.SendIpPacketAsync"/>
    /// (which adds the tun AF framing), inbound channel data is decapsulated and raised on the L3 channel. The SSH client's
    /// own receive loop pumps inbound packets and trips link-loss on a channel close / EOF; the supervisor / auto-reconnect
    /// (roadmap F.6) re-establishes a dead tunnel, mirroring the vtun / tinc drivers.
    /// <para>The client needs no elevation; the server needs <c>PermitTunnel</c> + a tun device (admin, server-side).</para>
    /// </summary>
    public sealed class SshConnection : ReconnectingVpnConnection, IDisposable, IAsyncDisposable
    {
        readonly string _host;
        readonly int _port;
        readonly SshConfig _config;
        readonly ISshTransportFactory _transportFactory;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly TunnelConfig _tunnelConfig;

        IByteStreamTransport? _stream;
        SshClient? _client;
        SshPacketChannel? _channel;
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;

        /// <summary>
        /// Creates a connection. <paramref name="config"/> is the static profile; <paramref name="transportFactory"/>
        /// opens the TCP connection (an in-process factory drives it offline). <paramref name="loggerFactory"/> receives
        /// diagnostic traces (null = no logging).
        /// </summary>
        public SshConnection(string host, int port, SshConfig config, ISshTransportFactory transportFactory,
            SshReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null,
            Func<long>? clock = null,
            ILoggerFactory? loggerFactory = null)
            : base(SshDriverConstants.DriverName, reconnectOptions ?? new SshReconnectOptions(), clock, loggerFactory)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
            _tunnelConfig = config.ToTunnelConfig();
        }

        /// <summary>The static tunnel configuration (tunnel address, DNS, routes, MTU).</summary>
        public TunnelConfig Config => _tunnelConfig;

        /// <summary>The local tunnel (overlay) address, if configured.</summary>
        public IPAddress? AssignedAddress => _config.TunnelAddress;

        /// <summary>Runs the handshake and returns once the tunnel is carrying traffic.</summary>
        public Task ConnectAsync(CancellationToken cancellationToken = default) => ConnectCoreAsync(cancellationToken);

        /// <inheritdoc/>
        protected override async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            IPAddress serverIp = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(LifetimeToken, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            IByteStreamTransport stream = await _transportFactory.ConnectAsync(new IPEndPoint(serverIp, _port), cancellationToken).ConfigureAwait(false);
            _stream = stream;

            // 1) SSH handshake + tun channel open.
            var client = new SshClient(stream, _config.ToClientOptions());
            Logger.LogHandshake(DriverName, $"SSH handshake to {_host}:{_port} as '{_config.Username}'");
            await client.ConnectAsync(cancellationToken).ConfigureAwait(false);
            _client = client;
            if (client.HostKey is not null)
                Logger.LogHandshake(DriverName, $"host key {client.HostKey.Sha256Fingerprint()}, cipher {client.CipherClientToServer}, tun channel open");

            // 2) Bind the L3 packet channel behind the stable facade.
            var channel = new SshPacketChannel(
                send: (packet, ct) => new ValueTask(client.SendIpPacketAsync(packet, ct)),
                mtu: _config.Mtu);
            _channel = channel;
            client.InboundIpPacket += OnInboundIpPacket;
            Facade.SetInner(channel);

            MarkRunning();

            // 3) Start the SSH receive loop (it raises InboundIpPacket and trips link-loss on close/EOF).
            _receiveTask = Task.Run(() => client.RunReceiveLoopAsync(reason => OnLinkLost(reason), loopToken), loopToken);

            Logger.LogHandshakeCompleted(DriverName);
            MarkConnected();
        }

        void OnInboundIpPacket(ReadOnlyMemory<byte> ipPacket) => _channel?.Deliver(ipPacket.Span);

        /// <inheritdoc/>
        public override async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            // Best-effort CHANNEL_CLOSE so the server drops the session promptly.
            SshClient? client = _client;
            if (client != null)
            {
                try { await client.CloseAsync(cancellationToken).ConfigureAwait(false); } catch { }
            }
            await DisconnectCoreAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        protected override async Task CleanupAttemptResourcesAsync()
        {
            StopAttemptLoop();

            SshClient? client = _client;
            _client = null;
            if (client != null) client.InboundIpPacket -= OnInboundIpPacket;

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }

            Task? receive = _receiveTask;
            _receiveTask = null;
            if (receive != null) { try { await receive.ConfigureAwait(false); } catch { } }
            loop?.Dispose();

            IByteStreamTransport? stream = _stream;
            _stream = null;
            if (stream != null) { try { await stream.DisposeAsync().ConfigureAwait(false); } catch { } }

            _channel = null;
        }

        /// <inheritdoc/>
        protected override void StopAttemptLoop()
        {
            // The SSH receive loop is cancelled via _loopCts in CleanupAttemptResourcesAsync; nothing timer-based here.
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            try { await DisconnectAsync().ConfigureAwait(false); } catch { }
            await DisposeCoreAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
