namespace TqkLibrary.VpnClient.Ipsec.Esp
{
    /// <summary>
    /// Shared ESP data-plane scaffolding for both transport mode (L2TP-over-IPsec) and tunnel mode (IKEv2): holds the
    /// current outbound+inbound SA, retains the pre-rekey SA briefly for make-before-break, and raises
    /// <see cref="RekeyNeeded"/> as the outbound sequence nears 2^32. Subclasses add the wire framing (UDP-encap vs
    /// bare IP) around <see cref="ProtectOutbound"/> / <see cref="TryUnprotectInbound"/>.
    /// </summary>
    public abstract class EspDataPlane
    {
        // High-watermark on the 2^32 outbound ESP sequence space: at ~75% we ask the driver to rekey, leaving ~1.07B
        // packets of headroom for the rekey round-trip to finish before the counter would overflow (RFC 4303 §3.3.3).
        protected const uint DefaultRekeyThreshold = 0xC000_0000u;
        // If a rekey hasn't installed a fresh SA, re-raise RekeyNeeded every ~1M further packets (≈1024 retries of headroom).
        protected const uint DefaultRekeyRetryStep = 0x0010_0000u;

        readonly object _swapLock = new();
        readonly uint _rekeyThreshold;
        readonly uint _rekeyRetryStep;
        EspSession _esp;                 // current SA: outbound + primary inbound
        EspSession? _previousInbound;    // the pre-rekey SA, kept briefly so in-flight packets still decrypt
        long _rekeySignalAt;             // next outbound sequence at which to (re)raise RekeyNeeded

        /// <summary>Creates the data plane over an established ESP session.</summary>
        /// <param name="rekeyAtSequence">Outbound sequence high-watermark that first triggers <see cref="RekeyNeeded"/>.</param>
        /// <param name="rekeyRetryStep">Packets between re-raising <see cref="RekeyNeeded"/> while no fresh SA arrives.</param>
        protected EspDataPlane(EspSession esp, uint rekeyAtSequence = DefaultRekeyThreshold, uint rekeyRetryStep = DefaultRekeyRetryStep)
        {
            _esp = esp;
            _rekeyThreshold = rekeyAtSequence;
            _rekeyRetryStep = Math.Max(1u, rekeyRetryStep);
            _rekeySignalAt = rekeyAtSequence;
        }

        /// <summary>
        /// Raised when the outbound ESP sequence number nears exhaustion (2^32) and the SA must be rekeyed before it
        /// would wrap. The driver responds with a CHILD_SA/Quick Mode rekey; re-raised periodically until a fresh SA is
        /// installed via <see cref="SwapSession"/>, which re-arms the watermark.
        /// </summary>
        public event Action? RekeyNeeded;

        /// <summary>
        /// Installs a rekeyed ESP session: new packets go out on it immediately, while the previous SA is retained
        /// for inbound only until <see cref="DropPreviousInbound"/> (make-before-break, so no packet is lost).
        /// </summary>
        public void SwapSession(EspSession next)
        {
            lock (_swapLock)
            {
                _previousInbound = _esp;
                _esp = next;
            }
            // Fresh SA → its sequence restarts at 0, so re-arm the exhaustion watermark.
            Interlocked.Exchange(ref _rekeySignalAt, _rekeyThreshold);
        }

        /// <summary>Drops the retained pre-rekey SA once the grace period has elapsed.</summary>
        public void DropPreviousInbound()
        {
            lock (_swapLock) _previousInbound = null;
        }

        /// <summary>
        /// Encrypts one payload on the current SA and signals rekey if the outbound sequence crosses the watermark.
        /// Non-async (keeps <c>Span</c> out of an async frame — C# 12 on the .NET 8 SDK).
        /// </summary>
        protected byte[] ProtectOutbound(ReadOnlySpan<byte> payload, byte nextHeader)
        {
            EspSession esp;
            lock (_swapLock) esp = _esp;
            byte[] espPacket = esp.Protect(payload, nextHeader);
            MaybeSignalRekey(esp.OutboundSequence);
            return espPacket;
        }

        /// <summary>
        /// Decrypts one inbound ESP packet on the current SA, falling back to the retained pre-rekey SA. SPIs are
        /// distinct per SA, so trying the wrong session simply fails its SPI check.
        /// </summary>
        protected bool TryUnprotectInbound(ReadOnlySpan<byte> espPacket, out byte[] payload, out byte nextHeader)
        {
            EspSession primary;
            EspSession? previous;
            lock (_swapLock) { primary = _esp; previous = _previousInbound; }

            return primary.TryUnprotect(espPacket, out payload, out nextHeader)
                || (previous is not null && previous.TryUnprotect(espPacket, out payload, out nextHeader));
        }

        // Once the outbound sequence crosses the watermark, raise RekeyNeeded exactly once per step (CAS so concurrent
        // sends don't double-fire), advancing the next trigger so a stalled rekey is retried without spamming per packet.
        void MaybeSignalRekey(uint sequence)
        {
            long signalAt = Interlocked.Read(ref _rekeySignalAt);
            if (sequence < signalAt) return;
            long next = Math.Min(signalAt + _rekeyRetryStep, uint.MaxValue);
            if (Interlocked.CompareExchange(ref _rekeySignalAt, next, signalAt) == signalAt)
                RekeyNeeded?.Invoke();
        }
    }
}
