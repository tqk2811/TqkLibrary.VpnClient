using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Ipsec.IpComp;

namespace TqkLibrary.VpnClient.Ipsec.Esp
{
    /// <summary>
    /// ESP tunnel-mode L3 data plane (RFC 4303): each outbound IP packet is ESP-protected whole with Next Header
    /// 4 (IPv4) / 41 (IPv6) and handed to the ESP datagram sink; inbound ESP packets are decrypted and the
    /// encapsulated IP packet is surfaced — demuxed by Next Header, no PPP/L2TP framing. This is what IKEv2 binds
    /// the userspace TCP/IP stack to. Make-before-break rekey is inherited from <see cref="EspDataPlane"/>.
    /// <para>When IPComp was negotiated in IKE_AUTH (RFC 7296 §3.10.1) an outbound CPI is supplied: each inner packet
    /// is DEFLATE-compressed (RFC 3173, "compress-then-encrypt") before ESP when that actually shrinks it (Next Header
    /// 108, IPComp), otherwise it goes out uncompressed as before; inbound Next Header 108 is inflated back to the
    /// original IP packet. With no CPI (the default) the channel behaves exactly as before — no compression, no
    /// IPComp demux.</para>
    /// </summary>
    public sealed class EspTunnelChannel : EspDataPlane, IPacketChannel
    {
        readonly Func<ReadOnlyMemory<byte>, Task> _sendEsp;
        readonly ushort? _outboundIpCompCpi;

        /// <summary>Creates the channel over an established ESP session and an ESP datagram sink.</summary>
        /// <param name="mtu">Inner-packet MTU advertised to the stack (tunnel overhead already deducted by the caller).</param>
        /// <param name="rekeyAtSequence">Outbound sequence high-watermark that first triggers <see cref="EspDataPlane.RekeyNeeded"/>.</param>
        /// <param name="rekeyRetryStep">Packets between re-raising <see cref="EspDataPlane.RekeyNeeded"/> while no fresh SA arrives.</param>
        /// <param name="outboundIpCompCpi">The peer's negotiated IPComp CPI (RFC 7296 §3.10.1) to stamp on compressed
        /// outbound packets; <c>null</c> (default) leaves IPComp inactive — traffic runs over plain ESP unchanged.</param>
        public EspTunnelChannel(EspSession esp, Func<ReadOnlyMemory<byte>, Task> sendEsp, int mtu,
            uint rekeyAtSequence = DefaultRekeyThreshold, uint rekeyRetryStep = DefaultRekeyRetryStep,
            ushort? outboundIpCompCpi = null)
            : base(esp, rekeyAtSequence, rekeyRetryStep)
        {
            _sendEsp = sendEsp;
            Mtu = mtu;
            _outboundIpCompCpi = outboundIpCompCpi;
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
            // IPComp (RFC 3173): when negotiated, DEFLATE-compress the inner packet under the peer's CPI and ESP it as
            // an IPComp datagram (Next Header 108) — but only when TryCompress shrinks it (non-expansion §2.2). If it
            // does not shrink (small/incompressible), fall through to plain ESP under the original Next Header.
            if (_outboundIpCompCpi is ushort cpi &&
                IpCompCodec.TryCompress(ipPacket, nextHeader, cpi, out byte[] ipcompDatagram))
                return ProtectOutbound(ipcompDatagram, EspConstants.NextHeaderIpComp);
            return ProtectOutbound(ipPacket, nextHeader);
        }

        /// <summary>Feeds one inbound ESP packet (decrypt → IPComp inflate if needed → IPv4/IPv6 demux), raising <see cref="InboundIpPacket"/>.</summary>
        public void OnEspPacket(ReadOnlyMemory<byte> espPacket)
        {
            if (!TryUnprotectInbound(espPacket.Span, out byte[] inner, out byte nextHeader)) return;
            // IPComp (RFC 3173): an IPComp datagram (Next Header 108) inflates back to the original IP packet and its
            // own Next Header; a corrupt/unsupported one is dropped. Only attempted when IPComp is active.
            if (_outboundIpCompCpi is not null && nextHeader == EspConstants.NextHeaderIpComp)
            {
                try { inner = IpCompCodec.Decompress(inner, out nextHeader); }
                catch (FormatException) { return; }
                catch (NotSupportedException) { return; }
            }
            // Only surface encapsulated IP packets; dummy/no-next-header padding (RFC 4303 §2.6) is silently dropped.
            if (nextHeader != EspConstants.NextHeaderIpv4 && nextHeader != EspConstants.NextHeaderIpv6) return;
            InboundIpPacket?.Invoke(inner);
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => default;
    }
}
