using TqkLibrary.Vpn.Ipsec.Ike.Enums;

namespace TqkLibrary.Vpn.Ipsec.Ike.Payloads
{
    /// <summary>
    /// Base for an IKEv2 payload. Each payload sits behind a 4-byte generic header
    /// (Next Payload, Critical+Reserved, Payload Length); subclasses write only their body.
    /// </summary>
    public abstract class IkePayload
    {
        /// <summary>The payload type used in the preceding "Next Payload" field.</summary>
        public abstract IkePayloadType Type { get; }

        /// <summary>Appends the payload body (everything after the 4-byte generic header) to <paramref name="output"/>.</summary>
        public abstract void WriteBody(List<byte> output);
    }
}
