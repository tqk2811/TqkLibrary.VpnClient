namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// Runs OpenVPN key-method-2 over the established TLS control channel (the <see cref="OpenVpnControlChannel.TlsStream"/>):
    /// writes the client's key source + options, reads the server's reply, then derives the AEAD data-channel keys.
    /// This is the client side; the server role lives only in tests. The TLS records themselves ride the reliability
    /// layer — here we only read/write the plaintext stream.
    /// </summary>
    public sealed class OpenVpnKeyNegotiation
    {
        // Server reply fixed prefix: uint32 0 (4) | key_method (1) | random1 (32) | random2 (32) | options length (2).
        const int ServerFixedPrefix = 4 + 1 + OpenVpnKeySource2.RandomSize * 2 + 2;
        const int OptionsLengthOffset = ServerFixedPrefix - 2;

        readonly Stream _tls;
        readonly ulong _clientSessionId;
        readonly ulong _serverSessionId;

        /// <summary>Creates the negotiation over <paramref name="tlsStream"/> with the two peers' session ids.</summary>
        public OpenVpnKeyNegotiation(Stream tlsStream, ulong clientSessionId, ulong serverSessionId)
        {
            _tls = tlsStream ?? throw new ArgumentNullException(nameof(tlsStream));
            _clientSessionId = clientSessionId;
            _serverSessionId = serverSessionId;
        }

        /// <summary>
        /// The OCC options string the server returned in its key-method-2 reply (empty until <see cref="NegotiateAsync"/>
        /// completes). Some servers echo their NCP cipher list here (<c>IV_CIPHERS=…</c>); the caller can mine it for the
        /// negotiated cipher when no <c>cipher</c> is later pushed in PUSH_REPLY (NCP-less servers).
        /// </summary>
        public string ServerOptions { get; private set; } = string.Empty;

        /// <summary>
        /// Sends the client key-method-2 message (with <paramref name="optionsString"/> and optional
        /// auth-user-pass / peer-info), reads the server's reply and returns the derived <see cref="OpenVpnKeyMaterial"/>
        /// (the caller slices it for the negotiated cipher after PUSH_REPLY). Throws
        /// <see cref="InvalidOperationException"/> if the reply is malformed.
        /// </summary>
        public async Task<OpenVpnKeyMaterial> NegotiateAsync(string optionsString,
            string? username = null, string? password = null, string? peerInfo = null, CancellationToken cancellationToken = default)
        {
            var clientKeySource = OpenVpnKeySource2.GenerateClient();
            byte[] clientMessage = OpenVpnKeyMethod2.BuildClientMessage(clientKeySource, optionsString, username, password, peerInfo);
            await _tls.WriteAsync(clientMessage, 0, clientMessage.Length, cancellationToken).ConfigureAwait(false);
            await _tls.FlushAsync(cancellationToken).ConfigureAwait(false);

            byte[] prefix = await ReadExactAsync(ServerFixedPrefix, cancellationToken).ConfigureAwait(false);
            int optionsLength = (prefix[OptionsLengthOffset] << 8) | prefix[OptionsLengthOffset + 1];

            byte[] message = new byte[ServerFixedPrefix + optionsLength];
            Array.Copy(prefix, message, ServerFixedPrefix);
            if (optionsLength > 0)
            {
                byte[] rest = await ReadExactAsync(optionsLength, cancellationToken).ConfigureAwait(false);
                Array.Copy(rest, 0, message, ServerFixedPrefix, optionsLength);
            }

            if (!OpenVpnKeyMethod2.TryParseServerMessage(message, out OpenVpnKeySource2 serverKeySource, out string serverOptions))
                throw new InvalidOperationException("Malformed OpenVPN key-method-2 server reply.");
            ServerOptions = serverOptions;

            byte[] key2 = OpenVpnKeyMethod2.DeriveKey2(clientKeySource, serverKeySource, _clientSessionId, _serverSessionId);
            return new OpenVpnKeyMaterial(key2);
        }

        async Task<byte[]> ReadExactAsync(int count, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n = await _tls.ReadAsync(buffer, read, count - read, cancellationToken).ConfigureAwait(false);
                if (n == 0) throw new EndOfStreamException("OpenVPN control channel closed during key negotiation.");
                read += n;
            }
            return buffer;
        }
    }
}
