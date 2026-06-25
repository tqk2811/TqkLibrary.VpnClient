using System.Net.Sockets;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Vtun.Auth;
using TqkLibrary.VpnClient.Vtun.Wire;
using TqkLibrary.VpnClient.Vtun.Wire.Enums;
using TqkLibrary.VpnClient.Vtun.Wire.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Vtun
{
    /// <summary>
    /// Owns the single vtun TCP byte stream and drives both phases over it: the authentication handshake (fixed 50-byte
    /// ASCII message blocks — greeting → <c>HOST:</c> → <c>OK CHAL:</c> → <c>CHAL:</c> → <c>OK FLAGS:</c>/<c>ERR</c>) and
    /// then the length-prefixed data framing (read/write a 2-byte big-endian header + payload). A single buffered reader
    /// backs both so a partial read straddling the handshake/data boundary is not lost. Not thread-safe for concurrent
    /// reads; the driver runs one receive loop and serialises writes.
    /// </summary>
    public sealed class VtunControlChannel
    {
        readonly IByteStreamTransport _stream;
        readonly byte[] _readBuffer = new byte[4096];
        readonly Queue<byte> _inbound = new();

        /// <summary>Wraps an already-connected vtun TCP byte stream.</summary>
        public VtunControlChannel(IByteStreamTransport stream)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        }

        /// <summary>
        /// The data-plane transform applied to each data frame's payload — set once after the handshake names the cipher
        /// (<c>null</c> = <c>encrypt no</c>, the payload is the bare tunnelled packet). Installed by the driver from the
        /// server-selected <see cref="VtunCipher"/>. Affects only data frames; control/auth framing is never transformed.
        /// </summary>
        public IVtunFrameTransform? DataTransform { get; set; }

        /// <summary>The host flags the server returned in <c>OK FLAGS:</c> (valid after <see cref="AuthenticateAsync"/>).</summary>
        public VtunHostFlags ServerFlags { get; private set; }

        /// <summary>The data-plane cipher id from the <c>E&lt;n&gt;</c> token (valid after <see cref="AuthenticateAsync"/>;
        /// <c>0</c> when the server selected no encryption or the legacy bare-<c>E</c> token).</summary>
        public int ServerCipherId { get; private set; }

        /// <summary>
        /// Runs the vtun client authentication against the server (vtun's <c>auth_client</c>): wait for the
        /// <c>VTUN ...</c> greeting, send <c>HOST: <paramref name="hostName"/></c>, receive the challenge, send the
        /// Blowfish-ECB(MD5(<paramref name="password"/>))-encrypted response, then parse the server's <c>OK FLAGS:</c>.
        /// On <c>ERR</c> (or a bad/closed exchange) throws <see cref="VpnAuthenticationException"/>. Returns the parsed
        /// server flags.
        /// </summary>
        public async Task<VtunHostFlags> AuthenticateAsync(string hostName, string password, CancellationToken cancellationToken)
        {
            // 1) Greeting — the server speaks first; the client only checks the "VTUN" prefix.
            string greeting = await ReadMessageAsync(cancellationToken).ConfigureAwait(false);
            if (!greeting.StartsWith("VTUN", StringComparison.Ordinal))
                throw new VpnAuthenticationException($"vtun server sent an unexpected greeting: '{greeting}'.");

            // 2) Select the host config block.
            await WriteMessageAsync($"HOST: {hostName}", cancellationToken).ConfigureAwait(false);

            // 3) Challenge — "OK CHAL: <ap-encoded>".
            string chalLine = await ReadMessageAsync(cancellationToken).ConfigureAwait(false);
            if (!chalLine.StartsWith("OK", StringComparison.Ordinal) || !VtunChallengeCodec.TryDecode(chalLine, out byte[] challenge))
                throw new VpnAuthenticationException($"vtun server did not send a valid challenge (got '{chalLine}').");

            // 4) Response — encrypt the challenge with the password and send it back.
            byte[] response = VtunChallengeCodec.EncryptChallenge(challenge, password);
            await WriteMessageAsync($"CHAL: {VtunChallengeCodec.Encode(response)}", cancellationToken).ConfigureAwait(false);

            // 5) Flags / error — "OK FLAGS: <...>" on success, "ERR" on a bad password / unknown host / lock denied.
            string flagsLine = await ReadMessageAsync(cancellationToken).ConfigureAwait(false);
            if (!flagsLine.StartsWith("OK", StringComparison.Ordinal) ||
                !VtunHostFlagsCodec.TryParse(flagsLine, out VtunHostFlags flags, out _, out int cipher, out _))
                throw new VpnAuthenticationException($"vtun server rejected authentication (got '{flagsLine}').");

            ServerFlags = flags;
            ServerCipherId = cipher;
            return flags;
        }

        // ---- handshake message blocks (50-byte NUL-padded ASCII) ----

        async Task WriteMessageAsync(string line, CancellationToken cancellationToken)
        {
            byte[] block = VtunMessageCodec.Encode(line);
            await _stream.WriteAsync(block, cancellationToken).ConfigureAwait(false);
        }

        async Task<string> ReadMessageAsync(CancellationToken cancellationToken)
        {
            byte[] block = await ReadExactAsync(VtunConstants.MessageSize, cancellationToken).ConfigureAwait(false);
            return VtunMessageCodec.Decode(block);
        }

        // ---- data-plane framing (shared buffered reader continues seamlessly after the handshake) ----

        /// <summary>
        /// Reads one data-plane frame. Returns the decoded header; for a <see cref="VtunFrameType.Data"/> frame
        /// <paramref name="payload"/> holds the payload bytes (a fresh array), otherwise it is empty. A clean peer close
        /// surfaces as <see cref="EndOfStreamException"/> from the underlying read.
        /// </summary>
        public async Task<VtunFrameHeader> ReadFrameAsync(CancellationToken cancellationToken)
        {
            byte[] header = await ReadExactAsync(VtunFrameCodec.HeaderSize, cancellationToken).ConfigureAwait(false);
            VtunFrameHeader decoded = VtunFrameCodec.DecodeHeader(header);
            if (decoded.Type == VtunFrameType.Data && decoded.Length > 0)
            {
                byte[] frame = await ReadExactAsync(decoded.Length, cancellationToken).ConfigureAwait(false);
                // Decrypt the data-frame payload when a cipher is in effect (a bad-pad frame decodes to empty → dropped).
                LastPayload = DataTransform is null ? frame : DataTransform.Decrypt(frame);
            }
            else
            {
                LastPayload = Array.Empty<byte>();
            }
            return decoded;
        }

        /// <summary>The payload of the most recent <see cref="ReadFrameAsync"/> data frame (empty for control frames).</summary>
        public byte[] LastPayload { get; private set; } = Array.Empty<byte>();

        /// <summary>
        /// Writes one data frame (2-byte length header + payload). When a <see cref="DataTransform"/> is installed the
        /// payload is encrypted first, so the framed length is the ciphertext length.
        /// </summary>
        public ValueTask WriteDataFrameAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
        {
            ReadOnlySpan<byte> body = DataTransform is null ? payload.Span : DataTransform.Encrypt(payload.Span);
            byte[] frame = VtunFrameCodec.EncodeData(body);
            return _stream.WriteAsync(frame, cancellationToken);
        }

        /// <summary>Writes one zero-payload control frame (echo request/reply, conn-close).</summary>
        public ValueTask WriteControlFrameAsync(VtunFrameType type, CancellationToken cancellationToken = default)
        {
            byte[] frame = VtunFrameCodec.EncodeControl(type);
            return _stream.WriteAsync(frame, cancellationToken);
        }

        // ---- buffered read-exactly over the byte stream ----

        async Task<byte[]> ReadExactAsync(int count, CancellationToken cancellationToken)
        {
            byte[] result = new byte[count];
            int filled = 0;

            // Drain any buffered bytes first.
            while (filled < count && _inbound.Count > 0)
                result[filled++] = _inbound.Dequeue();

            while (filled < count)
            {
                int read;
                try { read = await _stream.ReadAsync(_readBuffer, cancellationToken).ConfigureAwait(false); }
                catch (ObjectDisposedException) { throw new EndOfStreamException("vtun connection closed."); }
                catch (SocketException) { throw new EndOfStreamException("vtun connection reset."); }
                if (read <= 0) throw new EndOfStreamException("vtun server closed the connection.");

                int take = Math.Min(read, count - filled);
                for (int i = 0; i < take; i++) result[filled++] = _readBuffer[i];
                for (int i = take; i < read; i++) _inbound.Enqueue(_readBuffer[i]); // stash the overshoot for the next read
            }
            return result;
        }
    }
}
