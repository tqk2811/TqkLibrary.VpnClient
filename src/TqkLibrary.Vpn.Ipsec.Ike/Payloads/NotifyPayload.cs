using TqkLibrary.Vpn.Ipsec.Ike.Enums;

namespace TqkLibrary.Vpn.Ipsec.Ike.Payloads
{
    /// <summary>
    /// Notify payload: carries errors, status, NAT-detection hashes, transport-mode requests, etc.
    /// (RFC 7296 §3.10). Layout: Protocol ID(1) | SPI Size(1) | Notify Message Type(2) | SPI | Data.
    /// </summary>
    public sealed class NotifyPayload : IkePayload
    {
        /// <inheritdoc/>
        public override IkePayloadType Type => IkePayloadType.Notify;

        /// <summary>The protocol the notification concerns (often None for IKE-level notifies).</summary>
        public IkeProtocolId ProtocolId { get; set; } = IkeProtocolId.None;

        /// <summary>The notify message type.</summary>
        public ushort MessageType { get; set; }

        /// <summary>An optional SPI (e.g. for protocol-specific notifies).</summary>
        public byte[] Spi { get; set; } = Array.Empty<byte>();

        /// <summary>The notification data (e.g. a NAT-detection hash).</summary>
        public byte[] Data { get; set; } = Array.Empty<byte>();

        /// <summary>The strongly-typed notify type when it is one we recognise.</summary>
        public IkeNotifyMessageType KnownType => (IkeNotifyMessageType)MessageType;

        /// <summary>Creates an IKE-level notify of the given type carrying <paramref name="data"/>.</summary>
        public static NotifyPayload Create(IkeNotifyMessageType type, byte[] data)
            => new() { MessageType = (ushort)type, Data = data };

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output)
        {
            output.Add((byte)ProtocolId);
            output.Add((byte)Spi.Length);
            IkeBuffer.WriteUInt16(output, MessageType);
            output.AddRange(Spi);
            output.AddRange(Data);
        }

        internal static NotifyPayload Parse(ReadOnlySpan<byte> body)
        {
            int spiSize = body[1];
            return new NotifyPayload
            {
                ProtocolId = (IkeProtocolId)body[0],
                MessageType = IkeBuffer.ReadUInt16(body, 2),
                Spi = body.Slice(4, spiSize).ToArray(),
                Data = body.Slice(4 + spiSize).ToArray(),
            };
        }
    }
}
