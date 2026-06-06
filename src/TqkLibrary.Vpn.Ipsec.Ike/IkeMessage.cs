using TqkLibrary.Vpn.Ipsec.Ike.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.Payloads;

namespace TqkLibrary.Vpn.Ipsec.Ike
{
    /// <summary>
    /// A complete IKEv2 message: the 28-byte header plus a linked list of payloads (RFC 7296 §3.1).
    /// Encode/Decode handle the "Next Payload" chaining and per-payload generic headers.
    /// </summary>
    public sealed class IkeMessage
    {
        /// <summary>Fixed IKEv2 header length in bytes.</summary>
        public const int HeaderSize = 28;

        /// <summary>Version byte for IKEv2: major 2 (high nibble), minor 0.</summary>
        public const byte Version2 = 0x20;

        /// <summary>Initiator SPI (8 bytes), chosen by the SA initiator.</summary>
        public byte[] InitiatorSpi { get; set; } = new byte[8];

        /// <summary>Responder SPI (8 bytes), zero until the responder picks it in IKE_SA_INIT.</summary>
        public byte[] ResponderSpi { get; set; } = new byte[8];

        /// <summary>The exchange type.</summary>
        public IkeExchangeType ExchangeType { get; set; }

        /// <summary>Header flags (Initiator/Version/Response).</summary>
        public IkeHeaderFlags Flags { get; set; }

        /// <summary>Message ID (per-direction monotonic counter, RFC 7296 §2.2).</summary>
        public uint MessageId { get; set; }

        /// <summary>The ordered payload chain.</summary>
        public List<IkePayload> Payloads { get; } = new();

        /// <summary>Returns the first payload of type <typeparamref name="T"/>, or null.</summary>
        public T? Find<T>() where T : IkePayload => Payloads.OfType<T>().FirstOrDefault();

        /// <summary>Enumerates all Notify payloads in order.</summary>
        public IEnumerable<NotifyPayload> Notifies() => Payloads.OfType<NotifyPayload>();

        /// <summary>Serialises the message to its on-the-wire byte form.</summary>
        public byte[] Encode()
        {
            var body = new List<byte>();
            for (int i = 0; i < Payloads.Count; i++)
            {
                IkePayloadType next = i + 1 < Payloads.Count ? Payloads[i + 1].Type : IkePayloadType.None;
                int start = body.Count;
                body.Add((byte)next);
                body.Add(0); // critical(0) + reserved
                IkeBuffer.WriteUInt16(body, 0); // length placeholder
                Payloads[i].WriteBody(body);
                int length = body.Count - start;
                body[start + 2] = (byte)(length >> 8);
                body[start + 3] = (byte)length;
            }

            var message = new List<byte>(HeaderSize + body.Count);
            message.AddRange(InitiatorSpi);
            message.AddRange(ResponderSpi);
            message.Add((byte)(Payloads.Count > 0 ? Payloads[0].Type : IkePayloadType.None));
            message.Add(Version2);
            message.Add((byte)ExchangeType);
            message.Add((byte)Flags);
            IkeBuffer.WriteUInt32(message, MessageId);
            IkeBuffer.WriteUInt32(message, (uint)(HeaderSize + body.Count));
            message.AddRange(body);
            return message.ToArray();
        }

        /// <summary>Parses a message from its on-the-wire byte form. Throws on a malformed header/length.</summary>
        public static IkeMessage Decode(ReadOnlySpan<byte> data)
        {
            if (data.Length < HeaderSize) throw new ArgumentException("IKE message shorter than its header.", nameof(data));
            uint declaredLength = IkeBuffer.ReadUInt32(data, 24);
            if (declaredLength < HeaderSize || declaredLength > data.Length)
                throw new ArgumentException("IKE header length is out of range.", nameof(data));
            data = data.Slice(0, (int)declaredLength);

            var message = new IkeMessage
            {
                InitiatorSpi = data.Slice(0, 8).ToArray(),
                ResponderSpi = data.Slice(8, 8).ToArray(),
                ExchangeType = (IkeExchangeType)data[18],
                Flags = (IkeHeaderFlags)data[19],
                MessageId = IkeBuffer.ReadUInt32(data, 20),
            };

            var current = (IkePayloadType)data[16];
            int offset = HeaderSize;
            while (current != IkePayloadType.None && offset + 4 <= data.Length)
            {
                var next = (IkePayloadType)data[offset];
                int payloadLength = IkeBuffer.ReadUInt16(data, offset + 2);
                if (payloadLength < 4 || offset + payloadLength > data.Length) break;
                ReadOnlySpan<byte> payloadBody = data.Slice(offset + 4, payloadLength - 4);
                message.Payloads.Add(ParsePayload(current, payloadBody));
                offset += payloadLength;
                current = next;
            }
            return message;
        }

        static IkePayload ParsePayload(IkePayloadType type, ReadOnlySpan<byte> body) => type switch
        {
            IkePayloadType.SecurityAssociation => SecurityAssociationPayload.Parse(body),
            IkePayloadType.KeyExchange => KeyExchangePayload.Parse(body),
            IkePayloadType.Nonce => NoncePayload.Parse(body),
            IkePayloadType.Notify => NotifyPayload.Parse(body),
            _ => new RawPayload(type, body.ToArray()),
        };
    }
}
