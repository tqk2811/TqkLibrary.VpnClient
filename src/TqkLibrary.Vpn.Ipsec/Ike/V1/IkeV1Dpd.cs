using TqkLibrary.Vpn.Ipsec.Ike.V1.Enums;

namespace TqkLibrary.Vpn.Ipsec.Ike.V1
{
    /// <summary>
    /// Dead Peer Detection notify payloads (RFC 3706): an ISAKMP Notification body carrying R-U-THERE / R-U-THERE-ACK
    /// keyed by both cookies as the SPI and a monotonic sequence as the data. Exchanged inside an Informational message.
    /// </summary>
    public static class IkeV1Dpd
    {
        /// <summary>R-U-THERE notify message type.</summary>
        public const ushort RUThere = 36136;

        /// <summary>R-U-THERE-ACK notify message type.</summary>
        public const ushort RUThereAck = 36137;

        const int SpiSize = 16; // initiator cookie (8) + responder cookie (8)

        /// <summary>
        /// Builds a Notification body (RFC 2408 §3.14): DOI(4)=IPSEC | Protocol(1)=ISAKMP | SPI-Size(1)=16 |
        /// Notify-Type(2) | SPI(16=CKY-I‖CKY-R) | Notification-Data(4=sequence).
        /// </summary>
        public static byte[] BuildNotifyBody(byte[] initiatorCookie, byte[] responderCookie, ushort notifyType, uint sequence)
        {
            byte[] body = new byte[4 + 1 + 1 + 2 + SpiSize + 4];
            int offset = 0;
            // DOI = IPSEC (1).
            body[offset++] = 0; body[offset++] = 0; body[offset++] = 0; body[offset++] = (byte)IkeV1Constants.IpsecDoi;
            body[offset++] = IkeV1Constants.Protocol.Isakmp;
            body[offset++] = SpiSize;
            body[offset++] = (byte)(notifyType >> 8);
            body[offset++] = (byte)notifyType;
            System.Buffer.BlockCopy(initiatorCookie, 0, body, offset, 8); offset += 8;
            System.Buffer.BlockCopy(responderCookie, 0, body, offset, 8); offset += 8;
            body[offset++] = (byte)(sequence >> 24);
            body[offset++] = (byte)(sequence >> 16);
            body[offset++] = (byte)(sequence >> 8);
            body[offset] = (byte)sequence;
            return body;
        }

        /// <summary>Parses a Notification body, recovering its notify message type and sequence; false if it is not a DPD notify.</summary>
        public static bool TryParseNotify(byte[] body, out ushort notifyType, out uint sequence)
        {
            notifyType = 0;
            sequence = 0;
            if (body.Length < 8) return false;

            byte spiSize = body[5];
            int dataOffset = 8 + spiSize;
            notifyType = (ushort)((body[6] << 8) | body[7]);
            if (notifyType != RUThere && notifyType != RUThereAck) return false;
            if (body.Length < dataOffset + 4) return false;

            sequence = (uint)((body[dataOffset] << 24) | (body[dataOffset + 1] << 16) | (body[dataOffset + 2] << 8) | body[dataOffset + 3]);
            return true;
        }
    }
}
