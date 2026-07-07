using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using TqkLibrary.VpnClient.Drivers.AmneziaWg.Helpers;
using TqkLibrary.VpnClient.Drivers.AmneziaWg.Interfaces;
using TqkLibrary.VpnClient.Drivers.AmneziaWg.Models;
using TqkLibrary.VpnClient.WireGuard;

namespace TqkLibrary.VpnClient.Drivers.AmneziaWg
{
    /// <summary>
    /// The pure AmneziaWG codec (clean-room from the public awg spec — no code copied): it disguises a plain WireGuard
    /// datagram on the wire and reverses the disguise, but never touches WireGuard's cryptography — the AEAD payload is
    /// carried verbatim. A WireGuard datagram carries its message type as a <see cref="uint"/> little-endian at offset 0
    /// (byte 0 = 1/2/3/4, bytes 1..3 = 0 reserved), so the transform only rewrites those first bytes and, for handshake
    /// messages, prepends random junk:
    /// <list type="bullet">
    ///   <item><see cref="WireGuardConstants.MessageTypeInitiation"/> (1) ⇒ prepend <see cref="AmneziaWgParameters.S1"/>
    ///   junk bytes then write <see cref="AmneziaWgParameters.H1"/> as the magic.</item>
    ///   <item><see cref="WireGuardConstants.MessageTypeResponse"/> (2) ⇒ prepend <see cref="AmneziaWgParameters.S2"/>
    ///   junk bytes then write <see cref="AmneziaWgParameters.H2"/>.</item>
    ///   <item><see cref="WireGuardConstants.MessageTypeCookieReply"/> (3) ⇒ write <see cref="AmneziaWgParameters.H3"/> in
    ///   place, no padding.</item>
    ///   <item><see cref="WireGuardConstants.MessageTypeTransportData"/> (4) ⇒ write
    ///   <see cref="AmneziaWgParameters.H4"/> in place, no padding.</item>
    /// </list>
    /// The instance is safe to share between the outbound and inbound wrappers of one connection; it holds no per-packet
    /// state (junk-before-first-initiation timing is owned by <see cref="AmneziaWgDatagramTransport"/>).
    /// </summary>
    public sealed class AmneziaWgObfuscator
    {
        const int TypeFieldLength = 4; // WireGuard message type = uint32 little-endian at offset 0

        readonly AmneziaWgParameters _parameters;
        readonly IAmneziaWgRandom _random;

        /// <summary>
        /// Creates a codec for <paramref name="parameters"/> (validated eagerly — throws
        /// <see cref="ArgumentException"/> when invalid). <paramref name="random"/> supplies junk bytes and junk-packet
        /// sizes; null uses the shared cryptographic RNG (<see cref="CryptoAmneziaWgRandom.Shared"/>).
        /// </summary>
        public AmneziaWgObfuscator(AmneziaWgParameters parameters, IAmneziaWgRandom? random = null)
        {
            _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
            _parameters.Validate();
            _random = random ?? CryptoAmneziaWgRandom.Shared;
        }

        /// <summary>The parameter set this codec applies.</summary>
        public AmneziaWgParameters Parameters => _parameters;

        /// <summary>
        /// Turns a plain WireGuard datagram into its obfuscated wire form: rewrites the 4-byte message-type magic to the
        /// matching H value and, for handshake initiation/response, prepends S1/S2 random junk bytes ahead of it.
        /// </summary>
        /// <exception cref="ArgumentException"><paramref name="wgDatagram"/> is shorter than the 4-byte type field.</exception>
        public byte[] Obfuscate(ReadOnlySpan<byte> wgDatagram)
        {
            if (wgDatagram.Length < TypeFieldLength)
                throw new ArgumentException("A WireGuard datagram is at least 4 bytes (the message-type field).", nameof(wgDatagram));

            uint type = BinaryPrimitives.ReadUInt32LittleEndian(wgDatagram);
            switch (type)
            {
                case WireGuardConstants.MessageTypeInitiation:
                    return BuildPadded(wgDatagram, _parameters.S1, _parameters.H1);
                case WireGuardConstants.MessageTypeResponse:
                    return BuildPadded(wgDatagram, _parameters.S2, _parameters.H2);
                case WireGuardConstants.MessageTypeCookieReply:
                    return BuildInPlace(wgDatagram, _parameters.H3);
                case WireGuardConstants.MessageTypeTransportData:
                    return BuildInPlace(wgDatagram, _parameters.H4);
                default:
                    throw new ArgumentException($"Unknown WireGuard message type {type}; expected 1..4.", nameof(wgDatagram));
            }
        }

        /// <summary>Copies the datagram and overwrites its 4-byte type field with <paramref name="magic"/> (no padding).</summary>
        static byte[] BuildInPlace(ReadOnlySpan<byte> wgDatagram, uint magic)
        {
            byte[] wire = wgDatagram.ToArray();
            BinaryPrimitives.WriteUInt32LittleEndian(wire.AsSpan(0, TypeFieldLength), magic);
            return wire;
        }

        /// <summary>Prepends <paramref name="pad"/> random bytes, copies the datagram, and stamps <paramref name="magic"/> over its type field.</summary>
        byte[] BuildPadded(ReadOnlySpan<byte> wgDatagram, int pad, uint magic)
        {
            byte[] wire = new byte[pad + wgDatagram.Length];
            if (pad > 0)
            {
                byte[] junk = _random.NextBytes(pad);
                junk.AsSpan(0, pad).CopyTo(wire.AsSpan(0, pad));
            }
            wgDatagram.CopyTo(wire.AsSpan(pad));
            BinaryPrimitives.WriteUInt32LittleEndian(wire.AsSpan(pad, TypeFieldLength), magic);
            return wire;
        }

        /// <summary>
        /// Reverses <see cref="Obfuscate"/>: recovers the original WireGuard datagram from an obfuscated one. Returns
        /// <c>false</c> (and leaves <paramref name="wgDatagram"/> null) when the wire bytes match no magic — i.e. a junk
        /// packet, which the caller drops. The magics are tested in a fixed order so overlapping S1/S2 offsets can never
        /// be ambiguous (H1..H4 are validated distinct up front):
        /// <list type="number">
        ///   <item>bytes[0..4] == H4 ⇒ transport data (type 4);</item>
        ///   <item>bytes[0..4] == H3 ⇒ cookie reply (type 3);</item>
        ///   <item>len ≥ S1+4 and bytes[S1..S1+4] == H1 ⇒ initiation (type 1), drop the S1 prefix;</item>
        ///   <item>len ≥ S2+4 and bytes[S2..S2+4] == H2 ⇒ response (type 2), drop the S2 prefix.</item>
        /// </list>
        /// </summary>
        public bool TryDeobfuscate(ReadOnlySpan<byte> wire, out byte[] wgDatagram)
        {
            wgDatagram = null!;
            if (wire.Length < TypeFieldLength) return false;

            uint head = BinaryPrimitives.ReadUInt32LittleEndian(wire);
            if (head == _parameters.H4) { wgDatagram = Restore(wire, 0, WireGuardConstants.MessageTypeTransportData); return true; }
            if (head == _parameters.H3) { wgDatagram = Restore(wire, 0, WireGuardConstants.MessageTypeCookieReply); return true; }

            if (wire.Length >= _parameters.S1 + TypeFieldLength &&
                BinaryPrimitives.ReadUInt32LittleEndian(wire.Slice(_parameters.S1)) == _parameters.H1)
            {
                wgDatagram = Restore(wire, _parameters.S1, WireGuardConstants.MessageTypeInitiation);
                return true;
            }

            if (wire.Length >= _parameters.S2 + TypeFieldLength &&
                BinaryPrimitives.ReadUInt32LittleEndian(wire.Slice(_parameters.S2)) == _parameters.H2)
            {
                wgDatagram = Restore(wire, _parameters.S2, WireGuardConstants.MessageTypeResponse);
                return true;
            }

            return false; // matches nothing ⇒ junk ⇒ drop
        }

        /// <summary>Strips the <paramref name="prefix"/> junk bytes and restores the WireGuard type (type ‖ 0 0 0) at offset 0.</summary>
        static byte[] Restore(ReadOnlySpan<byte> wire, int prefix, byte wgType)
        {
            byte[] wgDatagram = wire.Slice(prefix).ToArray();
            BinaryPrimitives.WriteUInt32LittleEndian(wgDatagram.AsSpan(0, TypeFieldLength), wgType);
            return wgDatagram;
        }

        /// <summary>
        /// Produces the <see cref="AmneziaWgParameters.Jc"/> standalone junk packets emitted before the first handshake
        /// initiation — each a fresh random length in [<see cref="AmneziaWgParameters.Jmin"/>,
        /// <see cref="AmneziaWgParameters.Jmax"/>] of random content. Returns an empty list when <c>Jc</c> is 0.
        /// </summary>
        public IReadOnlyList<byte[]> GenerateJunkPackets()
        {
            if (_parameters.Jc == 0) return Array.Empty<byte[]>();
            var packets = new List<byte[]>(_parameters.Jc);
            for (int i = 0; i < _parameters.Jc; i++)
            {
                int size = _random.NextInt(_parameters.Jmin, _parameters.Jmax);
                packets.Add(_random.NextBytes(size));
            }
            return packets;
        }
    }
}
