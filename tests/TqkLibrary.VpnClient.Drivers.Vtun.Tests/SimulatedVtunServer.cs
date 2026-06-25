using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Vtun.Auth;
using TqkLibrary.VpnClient.Vtun.Wire;
using TqkLibrary.VpnClient.Vtun.Wire.Enums;
using TqkLibrary.VpnClient.Vtun.Wire.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Vtun.Tests
{
    /// <summary>
    /// An in-process stand-in for the vtund server side of one connection, used only to drive the real
    /// <see cref="VtunConnection"/> offline. It performs the server half of the challenge-response handshake
    /// (greeting → read <c>HOST:</c> → send a random challenge → verify the client's <c>CHAL:</c> by
    /// decrypting it with the password → send <c>OK FLAGS:</c>) and then runs a simple data loop: it answers an
    /// echo-request with an echo-reply and reflects each data frame back (so the client's outbound IP packet returns as
    /// an inbound one). It never originates traffic; the responder role lives only here.
    /// </summary>
    sealed class SimulatedVtunServer
    {
        readonly IByteStreamTransport _stream;
        readonly string _password;
        readonly VtunHostFlags _flags;
        readonly int _cipherId;
        readonly IVtunFrameTransform? _transform; // server-side data-plane transform when 'encrypt' is announced
        readonly Queue<byte> _inbound = new();
        readonly byte[] _readBuffer = new byte[4096];

        /// <summary>The challenge bytes this server generated (exposed for assertions).</summary>
        public byte[] Challenge { get; } = new byte[VtunConstants.ChallengeSize];

        /// <summary>True once a client's response verified against the password.</summary>
        public bool Authenticated { get; private set; }

        public SimulatedVtunServer(IByteStreamTransport serverSide, string password,
            VtunHostFlags flags = VtunHostFlags.Tcp | VtunHostFlags.Tun, int cipherId = 0)
        {
            _stream = serverSide;
            _password = password;
            _flags = flags;
            _cipherId = cipherId;
            if ((flags & VtunHostFlags.Encrypt) != 0)
                _transform = VtunFrameTransformFactory.TryCreate(VtunFrameTransformFactory.FromCipherId(cipherId), password);
            new Random(1234).NextBytes(Challenge); // deterministic for the test (real vtund uses RAND_bytes)
        }

        /// <summary>Runs the server side: handshake then the data loop, until cancelled or the pipe closes.</summary>
        public async Task RunAsync(CancellationToken cancellationToken)
        {
            try
            {
                await HandshakeAsync(cancellationToken).ConfigureAwait(false);
                if (!Authenticated) return;
                await DataLoopAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch (EndOfStreamException) { }
        }

        async Task HandshakeAsync(CancellationToken cancellationToken)
        {
            // 1) greeting
            await WriteMessageAsync("VTUN server ver 3.0.4 01/01/2020", cancellationToken).ConfigureAwait(false);

            // 2) read HOST:
            string hostLine = await ReadMessageAsync(cancellationToken).ConfigureAwait(false);
            if (!hostLine.StartsWith("HOST:", StringComparison.Ordinal)) { await WriteMessageAsync("ERR", cancellationToken).ConfigureAwait(false); return; }

            // 3) send challenge
            await WriteMessageAsync($"OK CHAL: {VtunChallengeCodec.Encode(Challenge)}", cancellationToken).ConfigureAwait(false);

            // 4) read CHAL: and verify (decrypt the response → must equal the original challenge)
            string chalLine = await ReadMessageAsync(cancellationToken).ConfigureAwait(false);
            if (!chalLine.StartsWith("CHAL:", StringComparison.Ordinal) || !VtunChallengeCodec.TryDecode(chalLine, out byte[] response))
            { await WriteMessageAsync("ERR", cancellationToken).ConfigureAwait(false); return; }

            byte[] recovered = VtunChallengeCodec.DecryptChallenge(response, _password);
            if (!recovered.AsSpan().SequenceEqual(Challenge)) { await WriteMessageAsync("ERR", cancellationToken).ConfigureAwait(false); return; }

            Authenticated = true;
            // 5) send flags (with the cipher id in the E<n> token when encryption is announced)
            await WriteMessageAsync($"OK FLAGS: {VtunHostFlagsCodec.Encode(_flags, cipher: _cipherId)}", cancellationToken).ConfigureAwait(false);
        }

        async Task DataLoopAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                byte[] header = await ReadExactAsync(VtunFrameCodec.HeaderSize, cancellationToken).ConfigureAwait(false);
                VtunFrameHeader decoded = VtunFrameCodec.DecodeHeader(header);
                switch (decoded.Type)
                {
                    case VtunFrameType.Data:
                        byte[] frame = decoded.Length > 0
                            ? await ReadExactAsync(decoded.Length, cancellationToken).ConfigureAwait(false)
                            : Array.Empty<byte>();
                        // Decrypt → re-encrypt so the reflected frame is independently transformed (matching real vtund,
                        // which decrypts inbound and re-encrypts outbound rather than echoing ciphertext verbatim).
                        byte[] plain = _transform is null ? frame : _transform.Decrypt(frame);
                        byte[] outbound = _transform is null ? plain : _transform.Encrypt(plain);
                        await _stream.WriteAsync(VtunFrameCodec.EncodeData(outbound), cancellationToken).ConfigureAwait(false);
                        break;
                    case VtunFrameType.EchoRequest:
                        await _stream.WriteAsync(VtunFrameCodec.EncodeControl(VtunFrameType.EchoReply), cancellationToken).ConfigureAwait(false);
                        break;
                    case VtunFrameType.ConnClose:
                        return;
                }
            }
        }

        // ---- message / frame I/O over the pipe ----

        ValueTask WriteMessageAsync(string line, CancellationToken cancellationToken)
            => _stream.WriteAsync(VtunMessageCodec.Encode(line), cancellationToken);

        async Task<string> ReadMessageAsync(CancellationToken cancellationToken)
            => VtunMessageCodec.Decode(await ReadExactAsync(VtunConstants.MessageSize, cancellationToken).ConfigureAwait(false));

        async Task<byte[]> ReadExactAsync(int count, CancellationToken cancellationToken)
        {
            byte[] result = new byte[count];
            int filled = 0;
            while (filled < count && _inbound.Count > 0) result[filled++] = _inbound.Dequeue();
            while (filled < count)
            {
                int read = await _stream.ReadAsync(_readBuffer, cancellationToken).ConfigureAwait(false);
                if (read <= 0) throw new EndOfStreamException("simulated vtun client closed.");
                int take = Math.Min(read, count - filled);
                for (int i = 0; i < take; i++) result[filled++] = _readBuffer[i];
                for (int i = take; i < read; i++) _inbound.Enqueue(_readBuffer[i]);
            }
            return result;
        }
    }
}
