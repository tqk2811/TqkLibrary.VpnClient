using TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Payloads;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V1
{
    /// <summary>
    /// An ISAKMP/IKEv1 message: the 28-byte header (initiator/responder cookies, exchange type, flags, message id,
    /// length) plus a Next-Payload-linked chain of payloads (RFC 2408 §3.1). Encrypted exchanges keep the header in
    /// the clear and cipher the payload chain; that ciphering lives in the IKEv1 session, not here.
    /// </summary>
    public sealed class IsakmpMessage
    {
        /// <summary>Fixed ISAKMP header length.</summary>
        public const int HeaderSize = 28;

        /// <summary>Version byte: major 1, minor 0.</summary>
        public const byte Version10 = 0x10;

        /// <summary>Initiator cookie (8 bytes) — the Phase 1 SPI.</summary>
        public byte[] InitiatorCookie { get; set; } = new byte[8];

        /// <summary>Responder cookie (8 bytes), zero until the responder picks it.</summary>
        public byte[] ResponderCookie { get; set; } = new byte[8];

        /// <summary>The exchange type (Main Mode, Quick Mode, Informational…).</summary>
        public IsakmpExchangeType ExchangeType { get; set; }

        /// <summary>Header flags (Encryption…).</summary>
        public IsakmpFlags Flags { get; set; }

        /// <summary>Message ID (0 for Phase 1; a random non-zero value per Quick Mode exchange).</summary>
        public uint MessageId { get; set; }

        /// <summary>The payload chain.</summary>
        public List<IsakmpPayload> Payloads { get; } = new();

        /// <summary>Returns the first payload of type <typeparamref name="T"/>, or null.</summary>
        public T? Find<T>() where T : IsakmpPayload => Payloads.OfType<T>().FirstOrDefault();

        /// <summary>Returns the first raw payload of the given type, or null.</summary>
        public IsakmpRawPayload? FindRaw(IsakmpPayloadType type)
            => Payloads.OfType<IsakmpRawPayload>().FirstOrDefault(p => p.Type == type);

        /// <summary>Serialises the message (header + cleartext payload chain).</summary>
        public byte[] Encode()
        {
            var body = new List<byte>();
            EncodePayloadChain(body, Payloads);
            IsakmpPayloadType first = Payloads.Count > 0 ? Payloads[0].Type : IsakmpPayloadType.None;

            var message = new List<byte>(HeaderSize + body.Count);
            WriteHeader(message, this, first, HeaderSize + body.Count);
            message.AddRange(body);
            return message.ToArray();
        }

        /// <summary>Parses a cleartext message (header + payload chain).</summary>
        public static IsakmpMessage Decode(ReadOnlySpan<byte> data)
        {
            if (data.Length < HeaderSize) throw new ArgumentException("ISAKMP message shorter than its header.", nameof(data));
            var message = ReadHeader(data, out IsakmpPayloadType first);
            ParsePayloadChain(data.Slice(HeaderSize), first, message.Payloads);
            return message;
        }

        /// <summary>Writes the 28-byte header into <paramref name="output"/> with the given first-payload type and total length.</summary>
        internal static void WriteHeader(List<byte> output, IsakmpMessage message, IsakmpPayloadType firstPayload, int totalLength)
        {
            output.AddRange(message.InitiatorCookie);
            output.AddRange(message.ResponderCookie);
            output.Add((byte)firstPayload);
            output.Add(Version10);
            output.Add((byte)message.ExchangeType);
            output.Add((byte)message.Flags);
            output.Add((byte)(message.MessageId >> 24)); output.Add((byte)(message.MessageId >> 16));
            output.Add((byte)(message.MessageId >> 8)); output.Add((byte)message.MessageId);
            output.Add((byte)(totalLength >> 24)); output.Add((byte)(totalLength >> 16));
            output.Add((byte)(totalLength >> 8)); output.Add((byte)totalLength);
        }

        /// <summary>Reads the header fields and the first-payload type.</summary>
        internal static IsakmpMessage ReadHeader(ReadOnlySpan<byte> data, out IsakmpPayloadType firstPayload)
        {
            firstPayload = (IsakmpPayloadType)data[16];
            return new IsakmpMessage
            {
                InitiatorCookie = data.Slice(0, 8).ToArray(),
                ResponderCookie = data.Slice(8, 8).ToArray(),
                ExchangeType = (IsakmpExchangeType)data[18],
                Flags = (IsakmpFlags)data[19],
                MessageId = (uint)((data[20] << 24) | (data[21] << 16) | (data[22] << 8) | data[23]),
            };
        }

        /// <summary>Appends the chained generic-header + body bytes for <paramref name="payloads"/>.</summary>
        internal static void EncodePayloadChain(List<byte> output, List<IsakmpPayload> payloads)
        {
            for (int i = 0; i < payloads.Count; i++)
            {
                IsakmpPayloadType next = i + 1 < payloads.Count ? payloads[i + 1].Type : IsakmpPayloadType.None;
                int start = output.Count;
                output.Add((byte)next);
                output.Add(0); // reserved
                output.Add(0); output.Add(0); // length placeholder
                payloads[i].WriteBody(output);
                int length = output.Count - start;
                output[start + 2] = (byte)(length >> 8);
                output[start + 3] = (byte)length;
            }
        }

        /// <summary>Parses a Next-Payload-linked chain starting at <paramref name="firstType"/>.</summary>
        internal static void ParsePayloadChain(ReadOnlySpan<byte> body, IsakmpPayloadType firstType, List<IsakmpPayload> into)
        {
            var current = firstType;
            int offset = 0;
            while (current != IsakmpPayloadType.None && offset + 4 <= body.Length)
            {
                var next = (IsakmpPayloadType)body[offset];
                int length = (body[offset + 2] << 8) | body[offset + 3];
                if (length < 4 || offset + length > body.Length) break;
                ReadOnlySpan<byte> payloadBody = body.Slice(offset + 4, length - 4);
                into.Add(current switch
                {
                    IsakmpPayloadType.SecurityAssociation => IsakmpSaPayload.Parse(payloadBody),
                    IsakmpPayloadType.Attribute => IsakmpConfigPayload.Parse(payloadBody),
                    _ => new IsakmpRawPayload(current, payloadBody.ToArray()),
                });
                offset += length;
                current = next;
            }
        }
    }
}
