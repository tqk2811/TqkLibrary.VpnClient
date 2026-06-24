using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Ssh.Auth;
using TqkLibrary.VpnClient.Ssh.Channel;
using TqkLibrary.VpnClient.Ssh.Cipher;
using TqkLibrary.VpnClient.Ssh.Transport;
using TqkLibrary.VpnClient.Ssh.Wire;
using TqkLibrary.VpnClient.Ssh.Wire.Enums;

namespace TqkLibrary.VpnClient.Ssh
{
    /// <summary>
    /// A minimal SSH-2 client that drives a full transport handshake over one <see cref="IByteStreamTransport"/> and then
    /// opens a <c>tun@openssh.com</c> point-to-point (layer-3) tunnel channel:
    /// version exchange → KEXINIT (negotiate curve25519-sha256 / ssh-ed25519 / an AEAD cipher) → curve25519 KEX →
    /// ed25519 host-key verify (signature over the exchange hash; optional pin callback) → NEWKEYS (install the
    /// directional ciphers) → userauth (publickey ed25519 or password) → CHANNEL_OPEN "tun@openssh.com".
    /// <para>
    /// After <see cref="ConnectAsync"/> succeeds the caller drives the data plane: <see cref="SendIpPacketAsync"/> sends a
    /// bare IP packet (wrapped in the tun AF framing + SSH_MSG_CHANNEL_DATA) and <see cref="RunReceiveLoopAsync"/> pumps
    /// inbound channel data, raising <see cref="InboundIpPacket"/> per packet and invoking the link-loss callback on EOF.
    /// Writes are serialised by the packet codec; the receive loop is single-threaded. This owns no sockets — the
    /// transport is injected.
    /// </para>
    /// </summary>
    public sealed class SshClient
    {
        readonly IByteStreamTransport _stream;
        readonly SshClientOptions _options;
        SshPacketCodec? _codec;

        // Channel state (valid after a successful tun channel open).
        uint _localChannel;
        uint _remoteChannel;
        uint _remoteWindow;
        uint _remoteMaxPacket;
        const uint InitialWindow = 2 * 1024 * 1024;
        const uint MaxChannelPacket = 32 * 1024;
        readonly SemaphoreSlim _channelLock = new(1, 1);

        /// <summary>Raised for each inbound IP packet decapsulated from tun channel data (valid only in the handler).</summary>
        public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

        /// <summary>The verified server host key (after a successful connect) — for fingerprint logging / pinning.</summary>
        public SshEd25519HostKey? HostKey { get; private set; }

        /// <summary>The negotiated cipher name client→server (after KEX).</summary>
        public string? CipherClientToServer { get; private set; }

        /// <summary>Creates a client over an already-connected byte stream with the given options.</summary>
        public SshClient(IByteStreamTransport stream, SshClientOptions options)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <summary>
        /// Runs the whole handshake and opens the tun channel. On return the tunnel is ready and the caller may start the
        /// receive loop and send packets. Throws <see cref="SshProtocolException"/> on any negotiation / auth / channel
        /// failure.
        /// </summary>
        public async Task ConnectAsync(CancellationToken cancellationToken)
        {
            // 1) Version exchange.
            var version = new SshVersionExchange(_stream);
            await version.ExchangeAsync(_options.ClientId, cancellationToken).ConfigureAwait(false);

            _codec = new SshPacketCodec(_stream);
            if (version.Leftover.Length > 0) _codec.PushBackBytes(version.Leftover);

            // 2) KEXINIT exchange.
            SshKexInit clientKexInit = SshKexInit.CreateClientDefault();
            byte[] clientKexInitPayload = clientKexInit.Encode();
            await _codec.WritePacketAsync(clientKexInitPayload, cancellationToken).ConfigureAwait(false);

            byte[] serverKexInitPayload = await ReadExpectingAsync(SshMessageNumber.KexInit, cancellationToken).ConfigureAwait(false);
            SshKexInit serverKexInit = SshKexInit.Decode(serverKexInitPayload);

            string kex = SshKexInit.Negotiate(clientKexInit.KexAlgorithms, serverKexInit.KexAlgorithms)
                ?? throw new SshProtocolException("No common key-exchange algorithm (need curve25519-sha256).");
            string hostKeyAlg = SshKexInit.Negotiate(clientKexInit.ServerHostKeyAlgorithms, serverKexInit.ServerHostKeyAlgorithms)
                ?? throw new SshProtocolException("No common host-key algorithm (need ssh-ed25519).");
            string cipherCs = SshKexInit.Negotiate(clientKexInit.EncryptionAlgorithmsClientToServer, serverKexInit.EncryptionAlgorithmsClientToServer)
                ?? throw new SshProtocolException("No common client→server cipher.");
            string cipherSc = SshKexInit.Negotiate(clientKexInit.EncryptionAlgorithmsServerToClient, serverKexInit.EncryptionAlgorithmsServerToClient)
                ?? throw new SshProtocolException("No common server→client cipher.");
            if (kex.StartsWith("curve25519-sha256", StringComparison.Ordinal) == false)
                throw new SshProtocolException($"Negotiated unsupported KEX '{kex}'.");
            CipherClientToServer = cipherCs;

            // 3) curve25519 key exchange.
            var keyExchange = new Curve25519KeyExchange();
            var initW = new SshWriter();
            initW.WriteByte((byte)SshMessageNumber.KexEcdhInit);
            initW.WriteString(keyExchange.EphemeralPublic);
            await _codec.WritePacketAsync(initW.ToArray(), cancellationToken).ConfigureAwait(false);

            byte[] replyPayload = await ReadExpectingAsync(SshMessageNumber.KexEcdhReply, cancellationToken).ConfigureAwait(false);
            var rr = new SshReader(replyPayload);
            rr.ReadByte(); // KexEcdhReply
            byte[] hostKeyBlob = rr.ReadStringBytes();   // K_S
            byte[] serverPublic = rr.ReadStringBytes();  // Q_S
            byte[] signature = rr.ReadStringBytes();     // signature over H

            keyExchange.ComputeSharedAndHash(serverPublic, hostKeyBlob, version.ClientId, version.ServerId,
                clientKexInitPayload, serverKexInitPayload);

            SshEd25519HostKey hostKey = SshEd25519HostKey.Parse(hostKeyBlob);
            if (!hostKey.VerifyExchangeHash(signature, keyExchange.ExchangeHash))
                throw new SshProtocolException("SSH host-key signature over the exchange hash did not verify.");
            HostKey = hostKey;
            // Optional host-key pin (TOFU): reject if the callback says no.
            if (_options.HostKeyValidator is not null && !_options.HostKeyValidator(hostKey))
                throw new SshProtocolException($"SSH host key rejected by the validator ({hostKey.Sha256Fingerprint()}).");

            // 4) NEWKEYS: send ours, expect theirs, then install the directional ciphers.
            await _codec.WritePacketAsync(new[] { (byte)SshMessageNumber.NewKeys }, cancellationToken).ConfigureAwait(false);
            byte[] serverNewKeys = await ReadExpectingAsync(SshMessageNumber.NewKeys, cancellationToken).ConfigureAwait(false);
            _ = serverNewKeys;

            byte[] sessionId = keyExchange.ExchangeHash;
            _codec.SetOutboundCipher(BuildCipher(cipherCs, keyExchange, sessionId, clientToServer: true));
            _codec.SetInboundCipher(BuildCipher(cipherSc, keyExchange, sessionId, clientToServer: false));

            // 5) User authentication.
            var auth = new SshUserAuth(
                (payload, ct) => _codec.WritePacketAsync(payload, ct),
                ct => _codec.ReadPacketAsync(ct),
                sessionId);
            await auth.RequestUserAuthServiceAsync(cancellationToken).ConfigureAwait(false);

            bool authed;
            if (_options.PrivateKeyEd25519 is not null)
                authed = await auth.AuthenticatePublicKeyAsync(_options.Username, _options.PrivateKeyEd25519, cancellationToken).ConfigureAwait(false);
            else if (_options.Password is not null)
                authed = await auth.AuthenticatePasswordAsync(_options.Username, _options.Password, cancellationToken).ConfigureAwait(false);
            else
                throw new SshProtocolException("No authentication method configured (need an Ed25519 private key or a password).");
            if (!authed)
                throw new SshProtocolException("SSH user authentication failed.");

            // 6) Open the tun@openssh.com channel.
            await OpenTunChannelAsync(cancellationToken).ConfigureAwait(false);
        }

        static ISshPacketCipher BuildCipher(string name, Curve25519KeyExchange kex, byte[] sessionId, bool clientToServer)
        {
            // Letters: IV c→s = 'A', s→c = 'B'; key c→s = 'C', s→c = 'D'.
            char ivLetter = clientToServer ? 'A' : 'B';
            char keyLetter = clientToServer ? 'C' : 'D';
            switch (name)
            {
                case "chacha20-poly1305@openssh.com":
                    return new ChaCha20Poly1305OpenSshCipher(kex.DeriveKey(keyLetter, sessionId, ChaCha20Poly1305OpenSshCipher.KeyMaterialBytes));
                case "aes256-gcm@openssh.com":
                {
                    byte[] key = kex.DeriveKey(keyLetter, sessionId, AesGcmOpenSshCipher.Aes256KeyBytes);
                    byte[] iv = kex.DeriveKey(ivLetter, sessionId, AesGcmOpenSshCipher.IvMaterialBytes);
                    return new AesGcmOpenSshCipher(key, iv);
                }
                case "aes128-gcm@openssh.com":
                {
                    byte[] key = kex.DeriveKey(keyLetter, sessionId, AesGcmOpenSshCipher.Aes128KeyBytes);
                    byte[] iv = kex.DeriveKey(ivLetter, sessionId, AesGcmOpenSshCipher.IvMaterialBytes);
                    return new AesGcmOpenSshCipher(key, iv);
                }
                default:
                    throw new SshProtocolException($"Unsupported cipher '{name}'.");
            }
        }

        async Task OpenTunChannelAsync(CancellationToken cancellationToken)
        {
            _localChannel = 0;
            var w = new SshWriter();
            w.WriteByte((byte)SshMessageNumber.ChannelOpen);
            w.WriteString("tun@openssh.com");
            w.WriteUInt32(_localChannel);    // sender (local) channel
            w.WriteUInt32(InitialWindow);    // initial window size
            w.WriteUInt32(MaxChannelPacket); // maximum packet size
            w.WriteUInt32((uint)SshTunChannelMode.PointToPoint);
            w.WriteUInt32(_options.RemoteTunUnit); // remote unit number (0x7fffffff = let the server choose)
            await _codec!.WritePacketAsync(w.ToArray(), cancellationToken).ConfigureAwait(false);

            // Wait for CHANNEL_OPEN_CONFIRMATION (skipping GLOBAL_REQUEST chatter).
            while (true)
            {
                byte[] msg = await _codec.ReadPacketAsync(cancellationToken).ConfigureAwait(false);
                if (msg.Length == 0) continue;
                var r = new SshReader(msg);
                var type = (SshMessageNumber)r.ReadByte();
                switch (type)
                {
                    case SshMessageNumber.ChannelOpenConfirmation:
                        r.ReadUInt32();                       // our channel
                        _remoteChannel = r.ReadUInt32();      // server channel
                        _remoteWindow = r.ReadUInt32();
                        _remoteMaxPacket = r.ReadUInt32();
                        return;
                    case SshMessageNumber.ChannelOpenFailure:
                        r.ReadUInt32();
                        uint reason = r.ReadUInt32();
                        string desc = r.ReadStringUtf8();
                        throw new SshProtocolException($"tun@openssh.com channel open failed (reason {reason}): {desc}. Is PermitTunnel enabled on the server?");
                    case SshMessageNumber.GlobalRequest:
                    case SshMessageNumber.Ignore:
                    case SshMessageNumber.Debug:
                        continue;
                    case SshMessageNumber.Disconnect:
                        throw new SshProtocolException("SSH server sent DISCONNECT while opening the tun channel.");
                    default:
                        continue; // ignore other transport chatter while waiting
                }
            }
        }

        /// <summary>Sends one bare IP packet over the tun channel (wraps it in the tun AF framing + SSH_MSG_CHANNEL_DATA).</summary>
        public async Task SendIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken)
        {
            if (_codec is null) return;
            byte[] tunData = SshTunFraming.Encapsulate(ipPacket.Span);

            var w = new SshWriter();
            w.WriteByte((byte)SshMessageNumber.ChannelData);
            w.WriteUInt32(_remoteChannel);
            w.WriteString(tunData);

            await _channelLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { await _codec.WritePacketAsync(w.ToArray(), cancellationToken).ConfigureAwait(false); }
            finally { _channelLock.Release(); }
        }

        /// <summary>
        /// Pumps inbound packets until cancellation, EOF or a peer close. CHANNEL_DATA → decapsulate → raise
        /// <see cref="InboundIpPacket"/>; WINDOW_ADJUST is consumed; CHANNEL_CLOSE/EOF/DISCONNECT calls
        /// <paramref name="onLinkLost"/> and returns. Other transport chatter (IGNORE, DEBUG, GLOBAL_REQUEST, PING) is
        /// ignored. Sends a local window-adjust as inbound data is consumed so the server keeps sending.
        /// </summary>
        public async Task RunReceiveLoopAsync(Action<string> onLinkLost, CancellationToken cancellationToken)
        {
            uint consumed = 0;
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    byte[] msg = await _codec!.ReadPacketAsync(cancellationToken).ConfigureAwait(false);
                    if (msg.Length == 0) continue;
                    var r = new SshReader(msg);
                    var type = (SshMessageNumber)r.ReadByte();
                    switch (type)
                    {
                        case SshMessageNumber.ChannelData:
                        {
                            r.ReadUInt32(); // recipient channel (ours)
                            ReadOnlySpan<byte> data = r.ReadString();
                            if (SshTunFraming.TryDecapsulate(data, out ReadOnlySpan<byte> ip, out _) && ip.Length > 0)
                                InboundIpPacket?.Invoke(ip.ToArray());

                            consumed += (uint)data.Length;
                            if (consumed >= InitialWindow / 2)
                            {
                                await SendWindowAdjustAsync(consumed, cancellationToken).ConfigureAwait(false);
                                consumed = 0;
                            }
                            break;
                        }
                        case SshMessageNumber.ChannelWindowAdjust:
                            r.ReadUInt32();
                            _remoteWindow += r.ReadUInt32();
                            break;
                        case SshMessageNumber.ChannelEof:
                            break;
                        case SshMessageNumber.ChannelClose:
                            onLinkLost("SSH server closed the tun channel");
                            return;
                        case SshMessageNumber.Disconnect:
                            onLinkLost("SSH server sent DISCONNECT");
                            return;
                        default:
                            break; // ignore other chatter
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (EndOfStreamException) { onLinkLost("SSH connection closed by peer"); }
            catch (SshProtocolException ex) { onLinkLost("SSH protocol error: " + ex.Message); }
        }

        async Task SendWindowAdjustAsync(uint bytes, CancellationToken cancellationToken)
        {
            var w = new SshWriter();
            w.WriteByte((byte)SshMessageNumber.ChannelWindowAdjust);
            w.WriteUInt32(_remoteChannel);
            w.WriteUInt32(bytes);
            await _channelLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { await _codec!.WritePacketAsync(w.ToArray(), cancellationToken).ConfigureAwait(false); }
            finally { _channelLock.Release(); }
        }

        /// <summary>Sends a best-effort CHANNEL_CLOSE then DISCONNECT so the server tears the session down promptly.</summary>
        public async Task CloseAsync(CancellationToken cancellationToken = default)
        {
            if (_codec is null) return;
            try
            {
                var close = new SshWriter();
                close.WriteByte((byte)SshMessageNumber.ChannelClose);
                close.WriteUInt32(_remoteChannel);
                await _codec.WritePacketAsync(close.ToArray(), cancellationToken).ConfigureAwait(false);
            }
            catch { }
        }

        async Task<byte[]> ReadExpectingAsync(SshMessageNumber expected, CancellationToken cancellationToken)
        {
            while (true)
            {
                byte[] msg = await _codec!.ReadPacketAsync(cancellationToken).ConfigureAwait(false);
                if (msg.Length == 0) continue;
                var type = (SshMessageNumber)msg[0];
                if (type == expected) return msg;
                switch (type)
                {
                    case SshMessageNumber.Ignore:
                    case SshMessageNumber.Debug:
                    case SshMessageNumber.GlobalRequest:
                        continue; // transport chatter — keep reading
                    case SshMessageNumber.Disconnect:
                        throw new SshProtocolException($"SSH server sent DISCONNECT while expecting {expected}.");
                    default:
                        throw new SshProtocolException($"Expected SSH message {expected}, got {type}.");
                }
            }
        }
    }
}
