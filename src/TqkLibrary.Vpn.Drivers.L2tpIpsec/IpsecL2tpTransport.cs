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
        readonly EspSession _esp;
        readonly Func<ReadOnlyMemory<byte>, Task> _sendEsp;

        /// <summary>Creates the transport over an established ESP session and an ESP datagram sink.</summary>
        public IpsecL2tpTransport(EspSession esp, Func<ReadOnlyMemory<byte>, Task> sendEsp)
        {
            _esp = esp;
            _sendEsp = sendEsp;
        }

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? DatagramReceived;

        /// <inheritdoc/>
        public Task SendAsync(ReadOnlyMemory<byte> l2tpDatagram)
        {
            byte[] udp = UdpEncapsulation.Build(UdpEncapsulation.L2tpPort, UdpEncapsulation.L2tpPort, l2tpDatagram.Span);
            byte[] esp = _esp.Protect(udp, EspConstants.NextHeaderUdp);
            return _sendEsp(esp);
        }

        /// <summary>Feeds one inbound ESP packet (decrypt → UDP/1701 → L2TP), raising <see cref="DatagramReceived"/>.</summary>
        public void OnEspPacket(ReadOnlyMemory<byte> espPacket)
        {
            if (!_esp.TryUnprotect(espPacket.Span, out byte[] udp, out byte nextHeader)) return;
            if (nextHeader != EspConstants.NextHeaderUdp) return;
            if (!UdpEncapsulation.TryParse(udp, out _, out ushort destinationPort, out byte[] l2tp)) return;
            if (destinationPort != UdpEncapsulation.L2tpPort) return;
            DatagramReceived?.Invoke(l2tp);
        }
    }
}
