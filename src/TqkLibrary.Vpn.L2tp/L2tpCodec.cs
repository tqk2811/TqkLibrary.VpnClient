using TqkLibrary.Vpn.L2tp.Enums;
using TqkLibrary.Vpn.L2tp.Models;

namespace TqkLibrary.Vpn.L2tp
{
    /// <summary>
    /// Encodes/decodes L2TPv2 messages (RFC 2661 §3.1). Control messages use the full header (T=L=S=1, Ver=2)
    /// followed by AVPs; data messages use a minimal header (T=0) followed by a raw PPP frame. Each message is one
    /// UDP datagram, so the Length field is optional on data and message boundaries come from the datagram.
    /// </summary>
    public static class L2tpCodec
    {
        const byte Version2 = 0x02;
        const byte FlagType = 0x80;     // T: control vs data
        const byte FlagLength = 0x40;   // L: Length field present
        const byte FlagSequence = 0x08; // S: Ns/Nr present
        const byte FlagOffset = 0x02;   // O: Offset field present

        /// <summary>True if the datagram is a control message (T bit set).</summary>
        public static bool IsControl(ReadOnlySpan<byte> datagram) => datagram.Length >= 2 && (datagram[0] & FlagType) != 0;

        /// <summary>Serialises a control message with its full header and AVPs.</summary>
        public static byte[] EncodeControl(L2tpControlMessage message)
        {
            var body = new List<byte>();
            if (!message.IsZeroLengthBody)
            {
                L2tpAvp.UInt16(L2tpAvpType.MessageType, (ushort)message.MessageType).Write(body);
                foreach (L2tpAvp avp in message.Avps) avp.Write(body);
            }

            int length = 12 + body.Count;
            var output = new List<byte>(length)
            {
                FlagType | FlagLength | FlagSequence, // T=1, L=1, S=1
                Version2,
                (byte)(length >> 8), (byte)length,
                (byte)(message.TunnelId >> 8), (byte)message.TunnelId,
                (byte)(message.SessionId >> 8), (byte)message.SessionId,
                (byte)(message.Ns >> 8), (byte)message.Ns,
                (byte)(message.Nr >> 8), (byte)message.Nr,
            };
            output.AddRange(body);
            return output.ToArray();
        }

        /// <summary>Parses a control message, including its AVP list (first AVP is the Message Type).</summary>
        public static L2tpControlMessage DecodeControl(ReadOnlySpan<byte> datagram)
        {
            byte flags = datagram[0];
            int offset = 2;
            int length = datagram.Length;
            if ((flags & FlagLength) != 0)
            {
                length = (datagram[2] << 8) | datagram[3];
                offset += 2;
            }
            ushort tunnelId = (ushort)((datagram[offset] << 8) | datagram[offset + 1]);
            ushort sessionId = (ushort)((datagram[offset + 2] << 8) | datagram[offset + 3]);
            offset += 4;
            ushort ns = 0, nr = 0;
            if ((flags & FlagSequence) != 0)
            {
                ns = (ushort)((datagram[offset] << 8) | datagram[offset + 1]);
                nr = (ushort)((datagram[offset + 2] << 8) | datagram[offset + 3]);
                offset += 4;
            }
            if ((flags & FlagOffset) != 0)
            {
                int offsetSize = (datagram[offset] << 8) | datagram[offset + 1];
                offset += 2 + offsetSize;
            }

            var message = new L2tpControlMessage { TunnelId = tunnelId, SessionId = sessionId, Ns = ns, Nr = nr };
            int end = Math.Min(length, datagram.Length);
            bool first = true;
            while (offset + 6 <= end)
            {
                int avpLength = ((datagram[offset] << 8) | datagram[offset + 1]) & 0x03FF;
                if (avpLength < 6 || offset + avpLength > end) break;
                L2tpAvp avp = L2tpAvp.Parse(datagram.Slice(offset, avpLength));
                if (first && avp.Type == L2tpAvpType.MessageType)
                {
                    message.MessageType = (L2tpMessageType)avp.AsUInt16();
                }
                else
                {
                    message.Avps.Add(avp);
                }
                first = false;
                offset += avpLength;
            }
            if (first) message.IsZeroLengthBody = true; // no AVPs at all
            return message;
        }

        /// <summary>Wraps a PPP frame in a minimal L2TP data header (T=0, no length/sequence).</summary>
        public static byte[] EncodeData(ushort tunnelId, ushort sessionId, ReadOnlySpan<byte> pppFrame)
        {
            byte[] datagram = new byte[6 + pppFrame.Length];
            datagram[0] = 0x00;       // T=0, L=0, S=0, O=0
            datagram[1] = Version2;
            datagram[2] = (byte)(tunnelId >> 8); datagram[3] = (byte)tunnelId;
            datagram[4] = (byte)(sessionId >> 8); datagram[5] = (byte)sessionId;
            pppFrame.CopyTo(datagram.AsSpan(6));
            return datagram;
        }

        /// <summary>Extracts the PPP frame from a data message, returning the tunnel/session ids and the frame bytes.</summary>
        public static bool TryDecodeData(ReadOnlySpan<byte> datagram, out ushort tunnelId, out ushort sessionId, out byte[] pppFrame)
        {
            tunnelId = 0; sessionId = 0; pppFrame = Array.Empty<byte>();
            if (datagram.Length < 6 || (datagram[0] & FlagType) != 0) return false;

            byte flags = datagram[0];
            int offset = 2;
            if ((flags & FlagLength) != 0) offset += 2;
            tunnelId = (ushort)((datagram[offset] << 8) | datagram[offset + 1]);
            sessionId = (ushort)((datagram[offset + 2] << 8) | datagram[offset + 3]);
            offset += 4;
            if ((flags & FlagSequence) != 0) offset += 4;
            if ((flags & FlagOffset) != 0)
            {
                int offsetSize = (datagram[offset] << 8) | datagram[offset + 1];
                offset += 2 + offsetSize;
            }
            if (offset > datagram.Length) return false;
            pppFrame = datagram.Slice(offset).ToArray();
            return true;
        }
    }
}
