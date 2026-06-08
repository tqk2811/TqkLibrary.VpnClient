using TqkLibrary.Vpn.Ipsec.Esp;
using TqkLibrary.Vpn.L2tp;

namespace TqkLibrary.Vpn.Drivers.L2tpIpsec
{
    /// <summary>
    /// Carries L2TP messages over IPsec: each L2TP datagram is wrapped in UDP/1701 and ESP-protected (transport
    /// mode), then handed to the UDP/4500 sender; inbound ESP packets are decrypted, the UDP/1701 payload is
    /// extracted, and the L2TP message is surfaced. This is the ESP data plane, identical for IKEv1 or IKEv2.
    /// </summary>
    public sealed class IpsecL2tpTransport : IL2tpTransport
    {
        readonly Func<ReadOnlyMemory<byte>, Task> _sendEsp;
        readonly object _swapLock = new();
        EspSession _esp;                 // current SA: outbound + primary inbound
        EspSession? _previousInbound;    // the pre-rekey SA, kept briefly so in-flight packets still decrypt

        /// <summary>Creates the transport over an established ESP session and an ESP datagram sink.</summary>
        public IpsecL2tpTransport(EspSession esp, Func<ReadOnlyMemory<byte>, Task> sendEsp)
        {
            _esp = esp;
            _sendEsp = sendEsp;
        }

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? DatagramReceived;

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
        }

        /// <summary>Drops the retained pre-rekey SA once the grace period has elapsed.</summary>
        public void DropPreviousInbound()
        {
            lock (_swapLock) _previousInbound = null;
        }

        /// <inheritdoc/>
        public Task SendAsync(ReadOnlyMemory<byte> l2tpDatagram)
        {
            EspSession esp;
            lock (_swapLock) esp = _esp;
            byte[] udp = UdpEncapsulation.Build(UdpEncapsulation.L2tpPort, UdpEncapsulation.L2tpPort, l2tpDatagram.Span);
            byte[] espPacket = esp.Protect(udp, EspConstants.NextHeaderUdp);
            return _sendEsp(espPacket);
        }

        /// <summary>Feeds one inbound ESP packet (decrypt → UDP/1701 → L2TP), raising <see cref="DatagramReceived"/>.</summary>
        public void OnEspPacket(ReadOnlyMemory<byte> espPacket)
        {
            EspSession primary;
            EspSession? previous;
            lock (_swapLock) { primary = _esp; previous = _previousInbound; }

            // SPIs are distinct per SA, so TryUnprotect on the wrong session simply fails the SPI check.
            if (!primary.TryUnprotect(espPacket.Span, out byte[] udp, out byte nextHeader)
                && (previous is null || !previous.TryUnprotect(espPacket.Span, out udp, out nextHeader)))
                return;

            if (nextHeader != EspConstants.NextHeaderUdp) return;
            if (!UdpEncapsulation.TryParse(udp, out _, out ushort destinationPort, out byte[] l2tp)) return;
            if (destinationPort != UdpEncapsulation.L2tpPort) return;
            DatagramReceived?.Invoke(l2tp);
        }
    }
}
