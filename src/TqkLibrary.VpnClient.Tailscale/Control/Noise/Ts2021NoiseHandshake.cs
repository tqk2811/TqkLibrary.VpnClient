using System.Text;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Aead;
using TqkLibrary.VpnClient.Crypto.Noise;

namespace TqkLibrary.VpnClient.Tailscale.Control.Noise
{
    /// <summary>
    /// The initiator half of the Tailscale ts2021 control handshake — Noise <c>IK</c> with the suite
    /// <c>Noise_IK_25519_ChaChaPoly_BLAKE2s</c> (control/controlbase). Unlike WireGuard's <c>IKpsk2</c> or Nebula's
    /// <c>IX</c>, the responder's static public key (the control server's <c>mkey:</c>, fetched from <c>/key</c>) is
    /// known up front, so it is folded into the transcript as the IK pre-message before message 1.
    /// <para>
    /// Token sequence (Noise IK):
    /// <list type="bullet">
    /// <item>pre-message <c>&lt;- s</c> (responder static) — <see cref="MixHash"/> of <c>rs</c> at init.</item>
    /// <item>message 1 <c>-&gt; e, es, s, ss</c> — initiator ephemeral (clear), DH(e,rs), encrypted initiator static, DH(s,rs), encrypted payload.</item>
    /// <item>message 2 <c>&lt;- e, ee, se</c> — responder ephemeral (clear), DH(e,re), DH(s,re), encrypted payload.</item>
    /// </list>
    /// On wire the messages carry only the cryptographic tokens (the ts2021 frame header is added by
    /// <see cref="Ts2021FrameCodec"/>): message 1 = <c>e.pub(32) || enc(s.pub)+tag(48) || enc(payload)+tag</c>;
    /// message 2 = <c>e.pub(32) || enc(payload)+tag</c>. Tailscale's payload here is empty, so message 1 carries an
    /// extra 16-byte tag for the empty payload and message 2 carries a 16-byte tag.
    /// </para>
    /// <para>
    /// Reuses the F.4 <see cref="NoiseSymmetricState"/> unchanged (BLAKE2s + HMAC-BLAKE2s KDF + ChaCha20-Poly1305) — the
    /// same engine WireGuard and Nebula drive; only the token order and the prologue differ. The prologue is
    /// <c>"Tailscale Control Protocol v" + protocolVersion</c>.
    /// </para>
    /// </summary>
    public sealed class Ts2021NoiseHandshake
    {
        /// <summary>The exact Noise protocol name string ts2021 uses (control/controlbase <c>protocolName</c>).</summary>
        public const string ProtocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

        /// <summary>The prologue prefix; the full prologue is this + the decimal protocol version.</summary>
        public const string ProtocolVersionPrefix = "Tailscale Control Protocol v";

        const int KeySize = 32;
        const int TagSize = 16;

        readonly IDhGroup _dh;
        readonly NoiseSymmetricState _state;
        readonly byte[] _localStaticPrivate;
        readonly byte[] _localStaticPublic;
        readonly byte[] _remoteStaticPublic;   // control server static (mkey), known up front
        readonly string _prologue;

        byte[]? _localEphemeralPrivate;
        byte[]? _remoteEphemeralPublic;
        bool _initiationSent;
        bool _completed;

        /// <summary>
        /// Creates the initiator. <paramref name="localStaticPrivate"/> is this client's 32-byte machine private key;
        /// <paramref name="remoteStaticPublic"/> is the control server's 32-byte machine public key (decoded from the
        /// <c>mkey:</c> the <c>/key</c> endpoint returns); <paramref name="protocolVersion"/> is the ts2021 protocol
        /// version negotiated in the frame header and the prologue (the Tailscale constant is 1). The crypto primitives
        /// default to the F.4 ones (Curve25519, BLAKE2s, HMAC-BLAKE2s, ChaCha20-Poly1305).
        /// </summary>
        public Ts2021NoiseHandshake(
            byte[] localStaticPrivate,
            byte[] remoteStaticPublic,
            int protocolVersion = 1,
            IDhGroup? dhGroup = null,
            IPrf? prf = null,
            IHashAlgo? hash = null,
            IAeadCipher? cipher = null)
        {
            if (localStaticPrivate is null || localStaticPrivate.Length != KeySize)
                throw new ArgumentException("Machine private key must be 32 bytes.", nameof(localStaticPrivate));
            if (remoteStaticPublic is null || remoteStaticPublic.Length != KeySize)
                throw new ArgumentException("Control machine public key must be 32 bytes.", nameof(remoteStaticPublic));

            _dh = dhGroup ?? new Curve25519DhGroup();
            _state = new NoiseSymmetricState(prf ?? new HmacBlake2sPrf(), hash ?? new Blake2s(), cipher ?? new ChaCha20Poly1305Cipher());
            _localStaticPrivate = (byte[])localStaticPrivate.Clone();
            _localStaticPublic = _dh.DerivePublicValue(localStaticPrivate);
            _remoteStaticPublic = (byte[])remoteStaticPublic.Clone();
            _prologue = ProtocolVersionPrefix + protocolVersion.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        /// <summary>This client's static (machine) public key — the same value as <c>mkey:</c> of this client.</summary>
        public byte[] LocalStaticPublic => (byte[])_localStaticPublic.Clone();

        /// <summary>Whether <see cref="ConsumeResponse"/> has completed the handshake (transport keys derivable).</summary>
        public bool IsCompleted => _completed;

        // Noise InitializeSymmetric(protocolName) + MixHash(prologue) + IK pre-message MixHash(rs).
        void Initialize()
        {
            _state.InitializeSymmetric(Encoding.ASCII.GetBytes(ProtocolName));
            _state.MixHash(Encoding.ASCII.GetBytes(_prologue));
            _state.MixHash(_remoteStaticPublic); // IK pre-message: <- s
        }

        /// <summary>
        /// Builds Noise IK message 1 (<c>e, es, s, ss</c>) carrying <paramref name="payload"/> (Tailscale uses an empty
        /// payload). Returns <c>e.pub(32) || enc(s.pub)+tag(48) || enc(payload)+tag(16)</c> — the bytes that follow the
        /// ts2021 initiation frame header.
        /// </summary>
        public byte[] CreateInitiation(ReadOnlySpan<byte> payload)
        {
            if (_initiationSent) throw new InvalidOperationException("CreateInitiation may be called only once.");
            _initiationSent = true;
            Initialize();

            _localEphemeralPrivate = _dh.GeneratePrivateKey();
            byte[] ePub = _dh.DerivePublicValue(_localEphemeralPrivate);
            _state.MixHash(ePub);                                                            // token e (clear)
            _state.MixKey(_dh.DeriveSharedSecret(_localEphemeralPrivate, _remoteStaticPublic)); // es: DH(e_i, s_r)

            byte[] sealedStatic = _state.EncryptAndHash(_localStaticPublic);                  // token s (AEAD)
            _state.MixKey(_dh.DeriveSharedSecret(_localStaticPrivate, _remoteStaticPublic));  // ss: DH(s_i, s_r)
            byte[] sealedPayload = _state.EncryptAndHash(payload);                            // payload (AEAD)

            return Concat(ePub, sealedStatic, sealedPayload);
        }

        /// <summary>
        /// Consumes Noise IK message 2 (<c>e, ee, se</c>): reads the responder ephemeral, runs the two DHs and opens the
        /// payload. Returns <c>false</c> on a malformed message or AEAD failure (forged/mismatched responder). Must
        /// follow <see cref="CreateInitiation"/>. On success the handshake is complete and <see cref="Split"/> may be
        /// called.
        /// </summary>
        public bool ConsumeResponse(ReadOnlySpan<byte> message, out byte[] payload)
        {
            payload = Array.Empty<byte>();
            if (!_initiationSent || _localEphemeralPrivate is null)
                throw new InvalidOperationException("ConsumeResponse requires a CreateInitiation first.");
            if (_completed) throw new InvalidOperationException("Handshake already completed.");
            if (message.Length < KeySize + TagSize) return false;

            _remoteEphemeralPublic = message.Slice(0, KeySize).ToArray();
            _state.MixHash(_remoteEphemeralPublic);                                            // token e (clear)
            _state.MixKey(_dh.DeriveSharedSecret(_localEphemeralPrivate, _remoteEphemeralPublic)); // ee: DH(e_i, e_r)
            _state.MixKey(_dh.DeriveSharedSecret(_localStaticPrivate, _remoteEphemeralPublic));     // se: DH(s_i, e_r)

            byte[]? openedPayload = _state.DecryptAndHash(message.Slice(KeySize));              // payload (AEAD)
            if (openedPayload is null) return false;

            payload = openedPayload;
            _completed = true;
            return true;
        }

        /// <summary>
        /// Noise <c>Split</c>: derives the transport key pair for the encrypted control channel. The initiator's send
        /// key is the first KDF output (so this side's <c>SendKey</c> equals the responder's receive key); inbound is
        /// decrypted with <c>ReceiveKey</c>. Must follow a completed <see cref="ConsumeResponse"/>.
        /// </summary>
        public (byte[] SendKey, byte[] ReceiveKey) Split()
        {
            if (!_completed) throw new InvalidOperationException("Split requires a completed handshake.");
            (byte[] first, byte[] second) = _state.Split();
            return (first, second); // initiator: first = send, second = receive
        }

        static byte[] Concat(byte[] a, byte[] b, byte[] c)
        {
            var result = new byte[a.Length + b.Length + c.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            Buffer.BlockCopy(c, 0, result, a.Length + b.Length, c.Length);
            return result;
        }
    }
}
