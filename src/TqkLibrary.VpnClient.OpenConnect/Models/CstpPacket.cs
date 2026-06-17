using TqkLibrary.VpnClient.OpenConnect.Enums;

namespace TqkLibrary.VpnClient.OpenConnect.Models
{
    /// <summary>
    /// A decoded CSTP packet: its <see cref="Type"/> and the <see cref="Payload"/> that followed the 8-byte header.
    /// Control packets (DPD/keep-alive/disconnect/terminate) normally carry an empty payload; <see cref="CstpPacketType.Data"/>
    /// and <see cref="CstpPacketType.Compressed"/> carry the tunnelled datagram.
    /// </summary>
    public sealed class CstpPacket
    {
        /// <summary>Creates a packet from a type and payload (the payload is taken by reference, not copied).</summary>
        public CstpPacket(CstpPacketType type, byte[] payload)
        {
            Type = type;
            Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        }

        /// <summary>The CSTP payload type (7th header byte).</summary>
        public CstpPacketType Type { get; }

        /// <summary>The bytes that followed the header (empty for control packets that carry no payload).</summary>
        public byte[] Payload { get; }

        /// <summary>True for the two payload-bearing types (<see cref="CstpPacketType.Data"/>/<see cref="CstpPacketType.Compressed"/>).</summary>
        public bool IsData => Type == CstpPacketType.Data || Type == CstpPacketType.Compressed;
    }
}
