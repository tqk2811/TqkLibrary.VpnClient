namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// Make-before-break wrapper over the AEAD data channel, mirroring the ESP data plane: new packets go out on the
    /// current key generation while the pre-rekey channel is kept for inbound only, so a soft-reset renegotiation
    /// (V2.e) loses no in-flight packet. <see cref="RekeyNeeded"/> fires as the outbound packet-id nears 2^32 (the GCM
    /// nonce must never repeat for a key). The control-plane half — running a fresh TLS handshake on a new key_id and
    /// calling <see cref="Swap"/> — lives in the driver.
    /// </summary>
    public sealed class OpenVpnDataPlane
    {
        // ~75% of the 2^32 packet-id space first asks for a rekey, leaving ~1.07B packets of headroom for it to finish.
        const uint DefaultRekeyThreshold = 0xC000_0000u;
        // If a rekey hasn't installed a fresh channel, re-raise RekeyNeeded every ~1M further packets.
        const uint DefaultRekeyRetryStep = 0x0010_0000u;

        readonly object _swapLock = new();
        readonly uint _rekeyThreshold;
        readonly uint _rekeyRetryStep;
        IOpenVpnDataChannel _current;
        IOpenVpnDataChannel? _previousInbound;
        long _rekeySignalAt;

        /// <summary>Creates the data plane over the established data channel (AEAD or CBC).</summary>
        /// <param name="current">The current key generation's data channel.</param>
        /// <param name="rekeyAtPacket">Outbound packet-id high-watermark that first triggers <see cref="RekeyNeeded"/>.</param>
        /// <param name="rekeyRetryStep">Packets between re-raising <see cref="RekeyNeeded"/> while no fresh channel arrives.</param>
        public OpenVpnDataPlane(IOpenVpnDataChannel current, uint rekeyAtPacket = DefaultRekeyThreshold, uint rekeyRetryStep = DefaultRekeyRetryStep)
        {
            _current = current ?? throw new ArgumentNullException(nameof(current));
            _rekeyThreshold = rekeyAtPacket;
            _rekeyRetryStep = Math.Max(1u, rekeyRetryStep);
            _rekeySignalAt = rekeyAtPacket;
        }

        /// <summary>
        /// Raised when the outbound packet-id nears 2^32 and a soft-reset renegotiation must install a fresh key before
        /// the nonce would wrap. Re-raised periodically until <see cref="Swap"/> installs a new channel.
        /// </summary>
        public event Action? RekeyNeeded;

        /// <summary>
        /// Installs a rekeyed data channel: new packets use it immediately while the previous one is retained for
        /// inbound only until <see cref="DropPreviousInbound"/> (make-before-break).
        /// </summary>
        public void Swap(IOpenVpnDataChannel next)
        {
            if (next is null) throw new ArgumentNullException(nameof(next));
            lock (_swapLock)
            {
                _previousInbound = _current;
                _current = next;
            }
            Interlocked.Exchange(ref _rekeySignalAt, _rekeyThreshold); // fresh channel restarts packet-id at 0
        }

        /// <summary>Drops the retained pre-rekey channel once the grace period has elapsed.</summary>
        public void DropPreviousInbound()
        {
            lock (_swapLock) _previousInbound = null;
        }

        /// <summary>Seals one outgoing packet on the current channel and signals rekey near packet-id exhaustion.</summary>
        public byte[] Protect(ReadOnlySpan<byte> plaintext)
        {
            IOpenVpnDataChannel current;
            lock (_swapLock) current = _current;
            byte[] wire = current.Protect(plaintext);
            MaybeSignalRekey(current.SentPacketCount);
            return wire;
        }

        /// <summary>
        /// Opens one inbound packet on the current channel, falling back to the retained pre-rekey channel (the wrong
        /// key simply fails the GCM tag). Returns false if neither accepts it.
        /// </summary>
        public bool TryUnprotect(ReadOnlySpan<byte> wire, out byte[] plaintext)
        {
            IOpenVpnDataChannel current;
            IOpenVpnDataChannel? previous;
            lock (_swapLock) { current = _current; previous = _previousInbound; }

            return current.TryUnprotect(wire, out plaintext)
                || (previous is not null && previous.TryUnprotect(wire, out plaintext));
        }

        // Raise RekeyNeeded once per step (CAS so concurrent sends don't double-fire), advancing the next trigger.
        void MaybeSignalRekey(uint packetCount)
        {
            long signalAt = Interlocked.Read(ref _rekeySignalAt);
            if (packetCount < signalAt) return;
            long next = Math.Min(signalAt + _rekeyRetryStep, uint.MaxValue);
            if (Interlocked.CompareExchange(ref _rekeySignalAt, next, signalAt) == signalAt)
                RekeyNeeded?.Invoke();
        }
    }
}
