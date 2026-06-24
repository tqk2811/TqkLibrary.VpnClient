using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Ssh.Transport
{
    /// <summary>
    /// The SSH protocol version exchange (RFC 4253 §4.2): each side sends an identification string
    /// <c>SSH-2.0-softwareversion[ comments]</c> terminated by CR LF, then reads the peer's. The server may emit other
    /// lines (not beginning with <c>SSH-</c>) before its identification string; those are skipped. The identification
    /// string <b>without</b> the trailing CR LF is what feeds the KEX exchange hash as V_C / V_S, so this returns the
    /// trimmed strings. Any bytes read past the server's CR LF (the start of its KEXINIT) are returned so the caller can
    /// push them back into the packet codec.
    /// </summary>
    public sealed class SshVersionExchange
    {
        /// <summary>The default client identification string (no CR LF).</summary>
        public const string DefaultClientId = "SSH-2.0-TqkLibrary_VpnClient";

        readonly IByteStreamTransport _stream;

        /// <summary>Wraps an already-connected byte stream.</summary>
        public SshVersionExchange(IByteStreamTransport stream) => _stream = stream ?? throw new ArgumentNullException(nameof(stream));

        /// <summary>The client identification string sent (no CR LF) — feeds the exchange hash as V_C. Valid after <see cref="ExchangeAsync"/>.</summary>
        public string ClientId { get; private set; } = DefaultClientId;

        /// <summary>The server identification string received (no CR LF) — feeds the exchange hash as V_S. Valid after <see cref="ExchangeAsync"/>.</summary>
        public string ServerId { get; private set; } = string.Empty;

        /// <summary>The bytes read after the server's CR LF (the beginning of its first binary packet); push these back into the codec.</summary>
        public byte[] Leftover { get; private set; } = Array.Empty<byte>();

        /// <summary>
        /// Sends the client identification string and reads the server's. <paramref name="clientId"/> overrides the
        /// default banner (no CR LF). Returns once both identification strings are known.
        /// </summary>
        public async Task ExchangeAsync(string? clientId = null, CancellationToken cancellationToken = default)
        {
            ClientId = string.IsNullOrEmpty(clientId) ? DefaultClientId : clientId!;
            byte[] toSend = Encoding.ASCII.GetBytes(ClientId + "\r\n");
            await _stream.WriteAsync(toSend, cancellationToken).ConfigureAwait(false);

            ServerId = await ReadIdentificationAsync(cancellationToken).ConfigureAwait(false);
            if (!ServerId.StartsWith("SSH-2.0-", StringComparison.Ordinal) && !ServerId.StartsWith("SSH-1.99-", StringComparison.Ordinal))
                throw new SshProtocolException($"Unsupported SSH server identification string: '{ServerId}'.");
        }

        async Task<string> ReadIdentificationAsync(CancellationToken cancellationToken)
        {
            // Read byte-by-byte assembling CR-LF-terminated lines; skip any line not starting with "SSH-" (RFC 4253 §4.2
            // allows the server to send banner lines first). Stash whatever was read past the SSH- line's LF.
            var line = new List<byte>(256);
            var overflow = new List<byte>();
            byte[] one = new byte[512];

            while (true)
            {
                int read = await _stream.ReadAsync(one.AsMemory(), cancellationToken).ConfigureAwait(false);
                if (read <= 0) throw new EndOfStreamException("SSH server closed the connection during the version exchange.");
                for (int i = 0; i < read; i++)
                {
                    byte b = one[i];
                    if (b == (byte)'\n')
                    {
                        // End of a line — drop a trailing CR.
                        if (line.Count > 0 && line[line.Count - 1] == (byte)'\r') line.RemoveAt(line.Count - 1);
                        string text = Encoding.ASCII.GetString(line.ToArray());
                        if (text.StartsWith("SSH-", StringComparison.Ordinal))
                        {
                            // Anything already read past this LF belongs to the first binary packet.
                            for (int j = i + 1; j < read; j++) overflow.Add(one[j]);
                            Leftover = overflow.ToArray();
                            return text;
                        }
                        line.Clear(); // a banner line — discard and keep reading
                    }
                    else
                    {
                        line.Add(b);
                        if (line.Count > 4096) throw new SshProtocolException("SSH server identification line too long.");
                    }
                }
            }
        }
    }
}
