using System;

namespace TqkLibrary.VpnClient.Drivers.AmneziaWg.Models
{
    /// <summary>
    /// The AmneziaWG obfuscation configuration both peers share (clean-room from the public awg spec — no code copied).
    /// The values drive how a plain WireGuard datagram is disguised on the wire without altering WireGuard crypto:
    /// <list type="bullet">
    ///   <item><b>Jc / Jmin / Jmax</b> — before the very first handshake initiation, emit <see cref="Jc"/> standalone junk
    ///   packets, each a random length in [<see cref="Jmin"/>, <see cref="Jmax"/>] bytes of random content.</item>
    ///   <item><b>S1 / S2</b> — prepend <see cref="S1"/> random junk bytes before a handshake <b>initiation</b> (type 1)
    ///   and <see cref="S2"/> before a handshake <b>response</b> (type 2); types 3/4 get no padding.</item>
    ///   <item><b>H1 / H2 / H3 / H4</b> — replace the original 4-byte little-endian message type (1/2/3/4) with these
    ///   custom <see cref="uint"/> magics so the leading bytes no longer look like WireGuard.</item>
    /// </list>
    /// Because both peers hold the same values, the receiver reverses the transform deterministically; a datagram that
    /// matches none of the magics is junk and is dropped.
    /// </summary>
    public sealed record AmneziaWgParameters
    {
        /// <summary>Number of standalone junk packets emitted before the first handshake initiation (≥ 0).</summary>
        public required int Jc { get; init; }

        /// <summary>Minimum size, in bytes, of each junk packet (≥ 0, ≤ <see cref="Jmax"/>).</summary>
        public required int Jmin { get; init; }

        /// <summary>Maximum size, in bytes, of each junk packet (≥ <see cref="Jmin"/>).</summary>
        public required int Jmax { get; init; }

        /// <summary>Number of random junk bytes prepended before a handshake initiation (type 1) packet (≥ 0).</summary>
        public required int S1 { get; init; }

        /// <summary>Number of random junk bytes prepended before a handshake response (type 2) packet (≥ 0).</summary>
        public required int S2 { get; init; }

        /// <summary>Custom magic replacing the original type-1 (initiation) message type. Must be distinct and &gt; 4.</summary>
        public required uint H1 { get; init; }

        /// <summary>Custom magic replacing the original type-2 (response) message type. Must be distinct and &gt; 4.</summary>
        public required uint H2 { get; init; }

        /// <summary>Custom magic replacing the original type-3 (cookie reply) message type. Must be distinct and &gt; 4.</summary>
        public required uint H3 { get; init; }

        /// <summary>Custom magic replacing the original type-4 (transport data) message type. Must be distinct and &gt; 4.</summary>
        public required uint H4 { get; init; }

        /// <summary>
        /// Validates the parameter set and throws <see cref="ArgumentException"/> on any violation: H1..H4 must all be
        /// greater than 4 (so they never collide with the real WireGuard types 1..4) and pairwise distinct (so inbound
        /// de-obfuscation is unambiguous); <see cref="Jmin"/> ≤ <see cref="Jmax"/>; and <see cref="Jc"/>,
        /// <see cref="Jmin"/>, <see cref="S1"/>, <see cref="S2"/> are non-negative.
        /// </summary>
        public void Validate()
        {
            if (Jc < 0) throw new ArgumentException("Jc must be non-negative.", nameof(Jc));
            if (Jmin < 0) throw new ArgumentException("Jmin must be non-negative.", nameof(Jmin));
            if (Jmax < Jmin) throw new ArgumentException("Jmax must be greater than or equal to Jmin.", nameof(Jmax));
            if (S1 < 0) throw new ArgumentException("S1 must be non-negative.", nameof(S1));
            if (S2 < 0) throw new ArgumentException("S2 must be non-negative.", nameof(S2));

            if (H1 <= 4 || H2 <= 4 || H3 <= 4 || H4 <= 4)
                throw new ArgumentException("H1..H4 must all be greater than 4 so they never collide with WireGuard message types 1..4.");

            if (H1 == H2 || H1 == H3 || H1 == H4 || H2 == H3 || H2 == H4 || H3 == H4)
                throw new ArgumentException("H1..H4 must be pairwise distinct so inbound de-obfuscation is unambiguous.");
        }
    }
}
