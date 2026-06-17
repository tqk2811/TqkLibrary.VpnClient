using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2
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
            EncodePayloadChain(body, Payloads);

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

            ParsePayloadChain(data.Slice(HeaderSize), (IkePayloadType)data[16], message.Payloads);
            return message;
        }

        /// <summary>Appends the chained generic-header + body bytes for <paramref name="payloads"/> to <paramref name="output"/>.</summary>
        internal static void EncodePayloadChain(List<byte> output, List<IkePayload> payloads)
        {
            for (int i = 0; i < payloads.Count; i++)
            {
                IkePayloadType next = i + 1 < payloads.Count ? payloads[i + 1].Type : IkePayloadType.None;
                int start = output.Count;
                output.Add((byte)next);
                output.Add(0); // critical(0) + reserved
                IkeBuffer.WriteUInt16(output, 0); // length placeholder
                payloads[i].WriteBody(output);
                int length = output.Count - start;
                output[start + 2] = (byte)(length >> 8);
                output[start + 3] = (byte)length;
            }
        }

        /// <summary>Parses a Next-Payload-linked chain starting at <paramref name="firstType"/> into <paramref name="into"/>.</summary>
        internal static void ParsePayloadChain(ReadOnlySpan<byte> body, IkePayloadType firstType, List<IkePayload> into)
        {
            var current = firstType;
            int offset = 0;
            while (current != IkePayloadType.None && offset + 4 <= body.Length)
            {
                var next = (IkePayloadType)body[offset];
                int payloadLength = IkeBuffer.ReadUInt16(body, offset + 2);
                if (payloadLength < 4 || offset + payloadLength > body.Length) break;
                into.Add(ParsePayload(current, body.Slice(offset + 4, payloadLength - 4)));
                offset += payloadLength;
                current = next;
            }
        }

        static IkePayload ParsePayload(IkePayloadType type, ReadOnlySpan<byte> body) => type switch
        {
            IkePayloadType.SecurityAssociation => SecurityAssociationPayload.Parse(body),
            IkePayloadType.KeyExchange => KeyExchangePayload.Parse(body),
            IkePayloadType.Nonce => NoncePayload.Parse(body),
            IkePayloadType.Notify => NotifyPayload.Parse(body),
            IkePayloadType.IdInitiator => IdentificationPayload.Parse(body, isInitiator: true),
            IkePayloadType.IdResponder => IdentificationPayload.Parse(body, isInitiator: false),
            IkePayloadType.Authentication => AuthenticationPayload.Parse(body),
            IkePayloadType.Certificate => CertificatePayload.Parse(body),
            IkePayloadType.CertificateRequest => CertificateRequestPayload.Parse(body),
            IkePayloadType.TrafficSelectorInitiator => TrafficSelectorPayload.Parse(body, isInitiator: true),
            IkePayloadType.TrafficSelectorResponder => TrafficSelectorPayload.Parse(body, isInitiator: false),
            IkePayloadType.Configuration => ConfigurationPayload.Parse(body),
            IkePayloadType.Delete => DeletePayload.Parse(body),
            IkePayloadType.Eap => EapPayload.Parse(body),
            _ => new RawPayload(type, body.ToArray()),
        };
    }
}
