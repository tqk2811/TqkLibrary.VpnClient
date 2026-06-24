using TqkLibrary.VpnClient.Crypto.Mppe.Enums;

namespace TqkLibrary.VpnClient.Crypto.Mppe
{
    /// <summary>
    /// One direction of an MPPE-encrypted PPP link (RFC 3078). Holds the RC4 keystream state, the start key,
    /// and the 12-bit coherency count, and re-keys per the negotiated mode:
    /// <list type="bullet">
    ///   <item><b>Stateless</b> (<c>MPPE-S</c>) — re-key before every packet; the FLUSHED (A) bit is set on every packet.</item>
    ///   <item><b>Stateful</b> — re-key only on the "flag" packet (low octet of the coherency count = 0xFF, i.e. every
    ///   256 packets) and on the first packet; FLUSHED is set only when the RC4 tables were just (re)initialized.</item>
    /// </list>
    /// The 2-byte MPPE header (A/B/C/D flags + 12-bit coherency count) is produced/consumed here; the protected
    /// payload is the PPP protocol + information field. <b>RC4 + MS-CHAPv2-derived keys are broken</b> — legacy only.
    /// </summary>
    public sealed class MppeSession
    {
        const int CoherencyMask = 0x0FFF; // 12-bit counter, wraps 4095 → 0
        const ushort FlagFlushed = 0x8000; // bit A in the 16-bit header word
        const ushort FlagEncrypted = 0x1000; // bit D

        readonly byte[] _startKey;
        readonly MppeKeyStrength _strength;
        readonly bool _stateless;

        byte[] _sessionKey;
        Rc4 _rc4;
        int _coherencyCount;
        bool _firstPacket = true;

        /// <summary>
        /// Creates a session direction from the 16-byte MPPE start key (<see cref="MsChapV2.DeriveMppeSendStartKey"/> /
        /// <see cref="MsChapV2.DeriveMppeReceiveStartKey"/>), the negotiated <paramref name="strength"/>, and whether
        /// stateless (<c>MPPE-S</c>) was negotiated.
        /// </summary>
        public MppeSession(byte[] startKey, MppeKeyStrength strength, bool stateless)
        {
            if (startKey is null) throw new ArgumentNullException(nameof(startKey));
            if (startKey.Length < MppeKeyDerivation.SessionKeyLength(strength))
                throw new ArgumentException("start key too short", nameof(startKey));

            // Truncate the 16-byte start key to the session-key length (RFC 3079: 8 bytes for 40/56-bit).
            int len = MppeKeyDerivation.SessionKeyLength(strength);
            _startKey = new byte[len];
            Buffer.BlockCopy(startKey, 0, _startKey, 0, len);

            _strength = strength;
            _stateless = stateless;
            _sessionKey = MppeKeyDerivation.DeriveInitialSessionKey(_startKey, strength);
            _rc4 = new Rc4(_sessionKey);
        }

        /// <summary>Current 12-bit coherency count (the next packet sent/expected uses this value).</summary>
        public int CoherencyCount => _coherencyCount;

        /// <summary>Current RC4 session key (copy) — for tests/diagnostics.</summary>
        public byte[] CurrentSessionKey => (byte[])_sessionKey.Clone();

        /// <summary>
        /// Encrypts one PPP payload and returns the full MPPE frame: <c>[2-byte header][RC4(payload)]</c>.
        /// Advances the coherency count and re-keys per the negotiated mode.
        /// </summary>
        public byte[] Encrypt(ReadOnlySpan<byte> payload)
        {
            bool flushed = AdvanceForSend();

            ushort header = (ushort)(_coherencyCount & CoherencyMask);
            header |= FlagEncrypted;
            if (flushed) header |= FlagFlushed;

            var frame = new byte[2 + payload.Length];
            frame[0] = (byte)(header >> 8);
            frame[1] = (byte)header;
            _rc4.Process(payload, frame.AsSpan(2));

            _coherencyCount = (_coherencyCount + 1) & CoherencyMask;
            return frame;
        }

        /// <summary>
        /// Decrypts one received MPPE frame (header + ciphertext) into the plaintext PPP payload. Honors the FLUSHED
        /// bit (re-init at the received coherency count) and re-keys on the stateful "flag" packet.
        /// </summary>
        public byte[] Decrypt(ReadOnlySpan<byte> frame)
        {
            if (frame.Length < 2) throw new ArgumentException("MPPE frame too short", nameof(frame));
            ushort header = (ushort)((frame[0] << 8) | frame[1]);
            int coherency = header & CoherencyMask;
            bool flushed = (header & FlagFlushed) != 0;
            if ((header & FlagEncrypted) == 0) throw new ArgumentException("MPPE frame is not marked encrypted", nameof(frame));

            SyncForReceive(coherency, flushed);

            var plaintext = new byte[frame.Length - 2];
            _rc4.Process(frame.Slice(2), plaintext);
            _coherencyCount = (coherency + 1) & CoherencyMask;
            return plaintext;
        }

        // Sender side: decide whether to re-key/flush before encrypting this packet.
        bool AdvanceForSend()
        {
            if (_stateless)
            {
                // Stateless (RFC 3078 §4.1): re-key before EVERY packet — including the first. The ctor loads the initial
                // session key (the equivalent of pppd/kernel mppe_init's mppe_rekey(initial=1)); the first transmitted
                // packet then runs mppe_rekey(0) once more, so it is encrypted with the *second* key, not the initial
                // one. Skipping the first re-key (the obvious-looking optimisation) leaves our packet-0 key one step
                // behind the peer ⇒ the server decrypts garbage and Protocol-Rejects it. FLUSHED is set on every packet.
                ReKey();
                _firstPacket = false;
                return true;
            }

            // Stateful: re-key on the first packet and whenever the low octet of the coherency count == 0xFF.
            if (_firstPacket)
            {
                _firstPacket = false;
                return true; // tables were just initialized with the initial key
            }
            if ((_coherencyCount & 0xFF) == 0xFF)
            {
                ReKey();
                return true;
            }
            return false;
        }

        // Receiver side: bring RC4 state to the received coherency count.
        void SyncForReceive(int coherency, bool flushed)
        {
            if (_stateless)
            {
                // Stateless: every received packet re-keys (mirror of the sender) — INCLUDING the first, so the receive
                // key tracks the peer's send key step-for-step from packet 0. The first packet carries the *second* key.
                ReKey();
                _firstPacket = false;
                _coherencyCount = coherency;
                return;
            }

            if (_firstPacket)
            {
                _firstPacket = false;
                // First stateful packet: initial key already loaded; honor flush by re-init at the initial key.
                _rc4 = new Rc4(_sessionKey);
                _coherencyCount = coherency;
                return;
            }

            // Stateful: re-key when the flag packet (low octet 0xFF) is reached.
            if ((coherency & 0xFF) == 0xFF || flushed)
            {
                if ((coherency & 0xFF) == 0xFF) ReKey();
                else _rc4 = new Rc4(_sessionKey); // flush without re-key: re-init tables at the current key
            }
            _coherencyCount = coherency;
        }

        void ReKey()
        {
            _sessionKey = MppeKeyDerivation.DeriveNextSessionKey(_startKey, _sessionKey, _strength);
            _rc4 = new Rc4(_sessionKey);
        }
    }
}
