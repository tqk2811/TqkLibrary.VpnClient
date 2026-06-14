using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Ipsec.Esp
{
    /// <summary>
    /// ESP tunnel-mode L3 data plane (RFC 4303): each outbound IP packet is ESP-protected whole with Next Header
    /// 4 (IPv4) / 41 (IPv6) and handed to the ESP datagram sink; inbound ESP packets are decrypted and the
    /// encapsulated IP packet is surfaced — demuxed by Next Header, no PPP/L2TP framing. This is what IKEv2 binds
    /// the userspace TCP/IP stack to. Make-before-break rekey is inherited from <see cref="EspDataPlane"/>.
    /// </summary>
    public sealed class EspTunnelChannel : EspDataPlane, IPacketChannel
    {
        readonly Func<ReadOnlyMemory<byte>, Task> _sendEsp;

        /// <summary>Creates the channel over an established ESP session and an ESP datagram sink.</summary>
        /// <param name="mtu">Inner-packet MTU advertised to the stack (tunnel overhead already deducted by the caller).</param>
        /// <param name="rekeyAtSequence">Outbound sequence high-watermark that first triggers <see cref="EspDataPlane.RekeyNeeded"/>.</param>
        /// <param name="rekeyRetryStep">Packets between re-raising <see cref="EspDataPlane.RekeyNeeded"/> while no fresh SA arrives.</param>
        public EspTunnelChannel(EspSession esp, Func<ReadOnlyMemory<byte>, Task> sendEsp, int mtu,
            uint rekeyAtSequence = DefaultRekeyThreshold, uint rekeyRetryStep = DefaultRekeyRetryStep)
            : base(esp, rekeyAtSequence, rekeyRetryStep)
        {
            _sendEsp = sendEsp;
            Mtu = mtu;
        }

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ip;

        /// <inheritdoc/>
        public int Mtu { get; }

        /// <inheritdoc/>
        public int MaxHeaderLength => 0;

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution => false;

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

        /// <inheritdoc/>
        public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
        {
            byte[]? espPacket = BuildEsp(ipPacket.Span);
            if (espPacket is null) return default;   // not a recognisable IPv4/IPv6 packet — drop
            return new ValueTask(_sendEsp(espPacket));
        }

        // Non-async: keeps the inner-packet Span out of the async frame (C# 12 on the .NET 8 SDK). Returns null when
        // the first nibble is neither 4 nor 6, so a malformed buffer is dropped rather than mislabelled.
        byte[]? BuildEsp(ReadOnlySpan<byte> ipPacket)
        {
            if (ipPacket.Length == 0) return null;
            byte version = (byte)(ipPacket[0] >> 4);
            byte nextHeader = version switch
            {
                4 => EspConstants.NextHeaderIpv4,
                6 => EspConstants.NextHeaderIpv6,
                _ => 0,
            };
            if (nextHeader == 0) return null;
            return ProtectOutbound(ipPacket, nextHeader);
        }

        /// <summary>Feeds one inbound ESP packet (decrypt → IPv4/IPv6 demux), raising <see cref="InboundIpPacket"/>.</summary>
        public void OnEspPacket(ReadOnlyMemory<byte> espPacket)
        {
            if (!TryUnprotectInbound(espPacket.Span, out byte[] inner, out byte nextHeader)) return;
            // Only surface encapsulated IP packets; dummy/no-next-header padding (RFC 4303 §2.6) is silently dropped.
            if (nextHeader != EspConstants.NextHeaderIpv4 && nextHeader != EspConstants.NextHeaderIpv6) return;
            InboundIpPacket?.Invoke(inner);
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => default;
    }
}
