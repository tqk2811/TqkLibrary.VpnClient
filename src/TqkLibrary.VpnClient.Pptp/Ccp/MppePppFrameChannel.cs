using System;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Crypto.Mppe;
using TqkLibrary.VpnClient.Crypto.Mppe.Enums;
using TqkLibrary.VpnClient.Ppp.Framing.Enums;
using TqkLibrary.VpnClient.Ppp.Interfaces;

namespace TqkLibrary.VpnClient.Pptp.Ccp
{
    /// <summary>
    /// The MPPE data-plane decorator for PPTP (RFC 3078/3079): an <see cref="IPppFrameChannel"/> that sits between
    /// the PPP engine (above) and the GRE channel (below, the <c>inner</c>). It runs CCP itself — the PPP engine
    /// never sees protocol 0x80FD — and, once CCP opens, encrypts/decrypts the PPP payloads via the pair of
    /// <see cref="MppeSession"/> derived from the MS-CHAPv2 result.
    /// <list type="bullet">
    ///   <item>Outbound LCP (0xC021) is always sent in the clear; everything else is MPPE-wrapped once active.</item>
    ///   <item>Inbound CCP (0x80FD) is consumed by the negotiator; Compressed (0x00FD) is decrypted; the rest passes through.</item>
    /// </list>
    /// <b>MPPE/RC4 is cryptographically broken</b> — legacy interop only.
    /// </summary>
    public sealed class MppePppFrameChannel : IPppFrameChannel
    {
        readonly IPppFrameChannel _inner;
        readonly Func<(string password, byte[] ntResponse)> _keyProvider;
        readonly CcpNegotiator _ccp;
        readonly TaskCompletionSource<bool> _ccpOpened =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        readonly object _gate = new object();
        bool _active;
        MppeSession? _sendSession;
        MppeSession? _recvSession;

        /// <summary>
        /// Wraps <paramref name="inner"/> (the GRE channel) with MPPE, deriving keys lazily from
        /// <paramref name="keyProvider"/> (the password + 24-byte MS-CHAPv2 NT-Response) once CCP opens.
        /// <paramref name="preferredStrength"/>/<paramref name="stateless"/> are the CCP offer.
        /// </summary>
        public MppePppFrameChannel(
            IPppFrameChannel inner,
            Func<(string password, byte[] ntResponse)> keyProvider,
            MppeKeyStrength preferredStrength = MppeKeyStrength.Bits128,
            bool stateless = false)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
            _ccp = new CcpNegotiator(SendCcp, preferredStrength, stateless);
            _ccp.Opened += OnCcpOpened;
            _inner.FrameReceived += OnInnerFrameReceived;
        }

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? FrameReceived;

        /// <summary>Completes once CCP reaches Opened and the MPPE sessions are active.</summary>
        public Task CcpOpenedTask => _ccpOpened.Task;

        /// <summary>Raised once when CCP opens and MPPE becomes active.</summary>
        public event Action? CcpOpened;

        /// <summary>True once CCP has opened and MPPE encryption/decryption is in effect.</summary>
        public bool IsActive { get { lock (_gate) return _active; } }

        /// <summary>Begins CCP negotiation by sending the first Configure-Request.</summary>
        public void StartCcp() => _ccp.Start();

        /// <inheritdoc/>
        public ValueTask SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken = default)
        {
            ReadOnlyMemory<byte> body = StripAddressControl(frame); // [proto:2][payload]
            if (body.Length < 2) return _inner.SendAsync(frame, cancellationToken);

            ushort proto = BinaryPrimitives.ReadUInt16BigEndian(body.Span);

            // LCP is always sent in the clear (it can run before/alongside CCP).
            if (proto == (ushort)PppProtocol.Lcp)
                return _inner.SendAsync(frame, cancellationToken);

            MppeSession? send;
            lock (_gate) { send = _active ? _sendSession : null; }
            if (send is null)
                return _inner.SendAsync(frame, cancellationToken);

            // Encrypt the whole [proto:2][payload] body; wrap as [FF 03][00 FD][cipher].
            byte[] cipher = send.Encrypt(body.Span);
            return _inner.SendAsync(WrapCompressed(cipher), cancellationToken);
        }

        void OnInnerFrameReceived(ReadOnlyMemory<byte> frame)
        {
            ReadOnlyMemory<byte> body = StripAddressControl(frame); // [proto:2][info]
            if (body.Length < 2) { FrameReceived?.Invoke(frame); return; }

            ushort proto = BinaryPrimitives.ReadUInt16BigEndian(body.Span);
            ReadOnlyMemory<byte> info = body.Slice(2);

            switch (proto)
            {
                case (ushort)PppProtocol.Ccp:
                    _ccp.HandlePacket(info.Span); // consumed here; never forwarded up
                    return;

                case (ushort)PppProtocol.Compressed:
                {
                    MppeSession? recv;
                    lock (_gate) { recv = _active ? _recvSession : null; }
                    if (recv is null) return; // not active yet — drop encrypted data we cannot read
                    byte[] recovered = recv.Decrypt(info.Span); // [proto:2][innerPayload]
                    FrameReceived?.Invoke(PrependAddressControl(recovered));
                    return;
                }

                default:
                    FrameReceived?.Invoke(frame); // LCP/CHAP/IPCP/IP/... pass through unchanged
                    return;
            }
        }

        void OnCcpOpened()
        {
            (string password, byte[] ntResponse) = _keyProvider();
            var negotiated = new MppeConfigOption(_ccp.NegotiatedStrength, _ccp.NegotiatedStateless);
            (MppeSession send, MppeSession receive) = MppeSessionFactory.CreateClientSessions(password, ntResponse, negotiated);

            lock (_gate)
            {
                _sendSession = send;
                _recvSession = receive;
                _active = true;
            }
            CcpOpened?.Invoke();
            _ccpOpened.TrySetResult(true);
        }

        // CCP control packets ride PPP protocol 0x80FD with the canonical [FF 03] prefix.
        void SendCcp(byte[] ccpPacket)
        {
            _ = _inner.SendAsync(WrapWithProtocol((ushort)PppProtocol.Ccp, ccpPacket));
        }

        static byte[] WrapCompressed(byte[] cipher) => WrapWithProtocol((ushort)PppProtocol.Compressed, cipher);

        // Builds [FF 03][proto:2 BE][info].
        static byte[] WrapWithProtocol(ushort proto, byte[] info)
        {
            byte[] framed = new byte[info.Length + 4];
            framed[0] = 0xFF;
            framed[1] = 0x03;
            BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(2), proto);
            Buffer.BlockCopy(info, 0, framed, 4, info.Length);
            return framed;
        }

        static ReadOnlyMemory<byte> StripAddressControl(ReadOnlyMemory<byte> frame)
        {
            ReadOnlySpan<byte> span = frame.Span;
            if (span.Length >= 2 && span[0] == 0xFF && span[1] == 0x03)
                return frame.Slice(2);
            return frame;
        }

        static ReadOnlyMemory<byte> PrependAddressControl(ReadOnlyMemory<byte> body)
        {
            var framed = new byte[body.Length + 2];
            framed[0] = 0xFF;
            framed[1] = 0x03;
            body.CopyTo(framed.AsMemory(2));
            return framed;
        }
    }
}
