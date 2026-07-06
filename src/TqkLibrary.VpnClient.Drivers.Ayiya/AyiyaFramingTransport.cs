using System;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Ayiya.Enums;

namespace TqkLibrary.VpnClient.Drivers.Ayiya
{
    /// <summary>
    /// An <see cref="IDatagramTransport"/> decorator that adds the AYIYA header (draft-massar-v6ops-ayiya-02) around an
    /// inner UDP pipe, so the reused <c>RawIpPassthroughChannel</c> above needs no AYIYA awareness — it just sees a raw
    /// IPv6 packet in each direction. <b>Outbound</b> wraps the inner IPv6 packet in a signed <see cref="AyiyaOpcode.Forward"/>
    /// datagram (next-header 41) stamped with the current epoch time. <b>Inbound</b> reads a datagram, verifies the
    /// shared-secret signature, checks the epoch time is within the configured clock-skew tolerance, and surfaces only a
    /// <see cref="AyiyaOpcode.Forward"/> IPv6 payload; anything else — a bad/absent signature, a stale epoch, a heartbeat
    /// (next-header 59 / echo), an unexpected next-header, or a runt — is <b>dropped</b> by returning 0 length, which the
    /// channel's receive loop treats as "nothing to deliver".
    /// <para>AYIYA signs integrity and guards replay; it does <b>not</b> encrypt the payload.</para>
    /// </summary>
    internal sealed class AyiyaFramingTransport : IDatagramTransport
    {
        readonly IDatagramTransport _inner;
        readonly AyiyaIdType _idType;
        readonly byte[] _identity;
        readonly AyiyaHashMethod _hashMethod;
        readonly AyiyaAuthMethod _authMethod;
        readonly byte[] _secretHash;
        readonly Func<uint> _epochClock;
        readonly int _clockSkewToleranceSeconds;
        byte[]? _receiveScratch;

        /// <summary>
        /// Wraps <paramref name="inner"/> with the AYIYA signer/verifier. <paramref name="secretHash"/> is
        /// <c>H(password)</c> (from <see cref="AyiyaPacket.HashPassword"/>). <paramref name="epochClock"/> supplies the epoch
        /// seconds (default: system UTC clock); <paramref name="clockSkewToleranceSeconds"/> is the maximum accepted
        /// |now − packet-epoch| on receive.
        /// </summary>
        public AyiyaFramingTransport(IDatagramTransport inner, AyiyaIdType idType, byte[] identity,
            AyiyaHashMethod hashMethod, AyiyaAuthMethod authMethod, byte[] secretHash,
            int clockSkewToleranceSeconds, Func<uint>? epochClock = null)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _identity = identity ?? throw new ArgumentNullException(nameof(identity));
            _secretHash = secretHash ?? throw new ArgumentNullException(nameof(secretHash));
            _idType = idType;
            _hashMethod = hashMethod;
            _authMethod = authMethod;
            _clockSkewToleranceSeconds = clockSkewToleranceSeconds < 0 ? 0 : clockSkewToleranceSeconds;
            _epochClock = epochClock ?? DefaultEpochClock;
        }

        /// <summary>The current epoch time (seconds since 1970-01-01 UTC) from the system clock.</summary>
        public static uint DefaultEpochClock() => (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        /// <inheritdoc/>
        public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => _inner.ConnectAsync(cancellationToken);

        /// <inheritdoc/>
        public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
        {
            // The inner payload is a raw IPv6 packet → wrap in a signed AYIYA forward datagram (next-header 41 = IPv6).
            byte[] framed = AyiyaPacket.Encode(_idType, _identity, _hashMethod, _authMethod, AyiyaOpcode.Forward,
                IpProtocol.Ipv6, _epochClock(), _secretHash, datagram.Span);
            return _inner.SendAsync(framed, cancellationToken);
        }

        /// <summary>
        /// Sends an AYIYA heartbeat: an <see cref="AyiyaOpcode.EchoRequest"/> with next-header 59 (no-next-header) and an
        /// empty payload, signed like any other datagram. Optional liveness keepalive; not scheduled automatically.
        /// </summary>
        public ValueTask SendHeartbeatAsync(CancellationToken cancellationToken = default)
        {
            byte[] framed = AyiyaPacket.Encode(_idType, _identity, _hashMethod, _authMethod, AyiyaOpcode.EchoRequest,
                IpProtocol.NoNextHeader, _epochClock(), _secretHash, ReadOnlySpan<byte>.Empty);
            return _inner.SendAsync(framed, cancellationToken);
        }

        /// <inheritdoc/>
        public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            byte[] scratch = _receiveScratch ??= new byte[ushort.MaxValue];
            int n = await _inner.ReceiveAsync(scratch, cancellationToken).ConfigureAwait(false);
            if (n <= 0) return 0;

            var datagram = new ReadOnlySpan<byte>(scratch, 0, n);
            if (!AyiyaPacket.TryParse(datagram, out AyiyaHeader header))
                return 0; // runt / truncated
            if (!AyiyaPacket.VerifySignature(datagram, header, _secretHash))
                return 0; // bad or absent signature / wrong shared secret
            if (!IsEpochWithinTolerance(header.EpochTime))
                return 0; // replay / clock skew beyond tolerance
            if (header.NextHeader != IpProtocol.Ipv6)
                return 0; // heartbeat (59), echo, or an unexpected inner protocol — nothing to deliver
            if (header.Opcode != AyiyaOpcode.Forward && header.Opcode != AyiyaOpcode.EchoRequestForward)
                return 0; // not a forwarded data packet
            if (header.PayloadLength <= 0)
                return 0; // no inner packet

            int copy = Math.Min(buffer.Length, header.PayloadLength);
            scratch.AsMemory(header.PayloadOffset, copy).CopyTo(buffer);
            return copy;
        }

        bool IsEpochWithinTolerance(uint packetEpoch)
        {
            long now = _epochClock();
            long diff = now - packetEpoch;
            if (diff < 0) diff = -diff;
            return diff <= _clockSkewToleranceSeconds;
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
