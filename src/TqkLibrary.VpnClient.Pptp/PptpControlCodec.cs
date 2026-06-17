using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using TqkLibrary.VpnClient.Pptp.Enums;
using TqkLibrary.VpnClient.Pptp.Interfaces;
using TqkLibrary.VpnClient.Pptp.Models;

namespace TqkLibrary.VpnClient.Pptp
{
    /// <summary>
    /// Wire codec for PPTP control messages (RFC 2637 §2). Every control packet starts with the fixed 8-byte
    /// common header — Length(2, big-endian) | PPTP-Message-Type(2) | Magic-Cookie(4 = 0x1A2B3C4D) — followed by
    /// Control-Message-Type(2) | Reserved0(2) and then the typed body. All multi-byte integers are big-endian
    /// (network byte order); fixed-length string fields are ASCII, NUL-padded.
    /// <para>
    /// <see cref="Encode"/> serialises a typed message; <see cref="Decode"/> parses one complete packet. The
    /// instance reassembler (<see cref="Append"/> + <see cref="TryReadMessage"/>) reconstructs whole control
    /// messages across arbitrary TCP read boundaries (the control connection is a byte stream).
    /// </para>
    /// Re-implemented from the published RFC 2637 wire format — not copied from any GPL implementation.
    /// </summary>
    public sealed class PptpControlCodec
    {
        /// <summary>The fixed common-header length: Length(2) + MessageType(2) + MagicCookie(4) + ControlMessageType(2) + Reserved0(2).</summary>
        public const int HeaderLength = 12;

        readonly List<byte> _buffer = new();

        // ---------------- Encode ----------------

        /// <summary>Serialises <paramref name="message"/> into a complete PPTP control packet (header + body).</summary>
        public static byte[] Encode(IPptpControlMessage message)
        {
            if (message is null) throw new ArgumentNullException(nameof(message));
            byte[] body = EncodeBody(message);
            int total = HeaderLength + body.Length;
            byte[] packet = new byte[total];

            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0, 2), (ushort)total);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)PptpMessageType.Control);
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4, 4), PptpControlHeader.MagicCookie);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(8, 2), (ushort)message.ControlMessageType);
            // bytes 10..11 = Reserved0 = 0 (already zero)
            body.CopyTo(packet, HeaderLength);
            return packet;
        }

        // ---------------- Decode ----------------

        /// <summary>
        /// Parses one complete control packet (the full header + body). Throws <see cref="FormatException"/> on a
        /// short buffer, a bad magic cookie, a non-control message type, or a length that does not match the buffer.
        /// </summary>
        public static IPptpControlMessage Decode(ReadOnlySpan<byte> packet)
        {
            if (packet.Length < HeaderLength)
                throw new FormatException("PPTP control packet shorter than the 12-byte header.");

            int length = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(0, 2));
            var messageType = (PptpMessageType)BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
            uint cookie = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(4, 4));
            var controlType = (PptpControlMessageType)BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(8, 2));

            if (cookie != PptpControlHeader.MagicCookie)
                throw new FormatException($"PPTP magic cookie invalid (0x{cookie:X8}, expected 0x{PptpControlHeader.MagicCookie:X8}).");
            if (messageType != PptpMessageType.Control)
                throw new FormatException($"PPTP message type {messageType} is not a control message.");
            if (length != packet.Length)
                throw new FormatException($"PPTP control packet length {packet.Length} does not match declared length {length}.");

            return DecodeBody(controlType, packet.Slice(HeaderLength));
        }

        // ---------------- Streaming reassembly ----------------

        /// <summary>Feeds a chunk of received control-connection bytes into the reassembly buffer.</summary>
        public void Append(ReadOnlySpan<byte> chunk)
        {
            // List<byte>.AddRange(ReadOnlySpan<byte>) isn't available on netstandard2.0; control packets are tiny
            // and infrequent, so a per-byte append is fine (zero-alloc is a Q.4 concern, not correctness).
            foreach (byte b in chunk) _buffer.Add(b);
        }

        /// <summary>
        /// Pulls the next fully-received control message if one is buffered; call in a loop after each
        /// <see cref="Append"/>. Returns false (leaving partial bytes buffered) until a complete packet has arrived.
        /// Throws <see cref="FormatException"/> if the buffered header is corrupt (bad magic / desynced stream).
        /// </summary>
        public bool TryReadMessage(out IPptpControlMessage message)
        {
            message = null!;
            if (_buffer.Count < HeaderLength) return false;

            int length = (_buffer[0] << 8) | _buffer[1];
            if (length < HeaderLength)
                throw new FormatException($"PPTP declared length {length} is shorter than the header.");
            if (_buffer.Count < length) return false;

            byte[] packet = new byte[length];
            for (int i = 0; i < length; i++) packet[i] = _buffer[i];
            _buffer.RemoveRange(0, length);
            message = Decode(packet);
            return true;
        }

        // ---------------- Body encoders ----------------

        static byte[] EncodeBody(IPptpControlMessage message) => message switch
        {
            StartControlConnectionRequest m => EncodeSccrq(m),
            StartControlConnectionReply m => EncodeSccrp(m),
            StopControlConnectionRequest m => EncodeStopRequest(m),
            StopControlConnectionReply m => EncodeStopReply(m),
            EchoRequest m => EncodeEchoRequest(m),
            EchoReply m => EncodeEchoReply(m),
            OutgoingCallRequest m => EncodeOcrq(m),
            OutgoingCallReply m => EncodeOcrp(m),
            SetLinkInfo m => EncodeSetLinkInfo(m),
            CallClearRequest m => EncodeCallClear(m),
            CallDisconnectNotify m => EncodeCdn(m),
            _ => throw new NotSupportedException($"No encoder for PPTP control message {message.ControlMessageType}."),
        };

        static byte[] EncodeSccrq(StartControlConnectionRequest m)
        {
            // ProtocolVersion(2) Reserved1(2) Framing(4) Bearer(4) MaxChannels(2) FirmwareRev(2) HostName(64) VendorName(64)
            byte[] b = new byte[2 + 2 + 4 + 4 + 2 + 2 + 64 + 64];
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(0, 2), m.ProtocolVersion);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4, 4), (uint)m.FramingCapabilities);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(8, 4), (uint)m.BearerCapabilities);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(12, 2), m.MaximumChannels);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(14, 2), m.FirmwareRevision);
            WriteFixedString(b.AsSpan(16, 64), m.HostName);
            WriteFixedString(b.AsSpan(80, 64), m.VendorName);
            return b;
        }

        static byte[] EncodeSccrp(StartControlConnectionReply m)
        {
            // ProtocolVersion(2) ResultCode(1) ErrorCode(1) Framing(4) Bearer(4) MaxChannels(2) FirmwareRev(2) HostName(64) VendorName(64)
            byte[] b = new byte[2 + 1 + 1 + 4 + 4 + 2 + 2 + 64 + 64];
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(0, 2), m.ProtocolVersion);
            b[2] = (byte)m.ResultCode;
            b[3] = m.ErrorCode;
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4, 4), (uint)m.FramingCapabilities);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(8, 4), (uint)m.BearerCapabilities);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(12, 2), m.MaximumChannels);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(14, 2), m.FirmwareRevision);
            WriteFixedString(b.AsSpan(16, 64), m.HostName);
            WriteFixedString(b.AsSpan(80, 64), m.VendorName);
            return b;
        }

        static byte[] EncodeStopRequest(StopControlConnectionRequest m)
        {
            // Reason(1) Reserved1(1) Reserved2(2)
            byte[] b = new byte[4];
            b[0] = m.Reason;
            return b;
        }

        static byte[] EncodeStopReply(StopControlConnectionReply m)
        {
            // ResultCode(1) ErrorCode(1) Reserved1(2)
            byte[] b = new byte[4];
            b[0] = (byte)m.ResultCode;
            b[1] = m.ErrorCode;
            return b;
        }

        static byte[] EncodeEchoRequest(EchoRequest m)
        {
            // Identifier(4)
            byte[] b = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(b, m.Identifier);
            return b;
        }

        static byte[] EncodeEchoReply(EchoReply m)
        {
            // Identifier(4) ResultCode(1) ErrorCode(1) Reserved1(2)
            byte[] b = new byte[8];
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(0, 4), m.Identifier);
            b[4] = (byte)m.ResultCode;
            b[5] = m.ErrorCode;
            return b;
        }

        static byte[] EncodeOcrq(OutgoingCallRequest m)
        {
            // CallID(2) CallSerial(2) MinBPS(4) MaxBPS(4) BearerType(4) FramingType(4)
            // RecvWindow(2) ProcessingDelay(2) PhoneNumberLength(2) Reserved1(2) PhoneNumber(64) Subaddress(64)
            byte[] b = new byte[2 + 2 + 4 + 4 + 4 + 4 + 2 + 2 + 2 + 2 + 64 + 64];
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(0, 2), m.CallId);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2, 2), m.CallSerialNumber);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4, 4), m.MinBps);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(8, 4), m.MaxBps);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(12, 4), m.BearerType);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(16, 4), m.FramingType);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(20, 2), m.PacketRecvWindowSize);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(22, 2), m.PacketProcessingDelay);
            int phoneLen = Encoding.ASCII.GetByteCount(m.PhoneNumber ?? string.Empty);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(24, 2), (ushort)System.Math.Min(phoneLen, 64));
            WriteFixedString(b.AsSpan(28, 64), m.PhoneNumber);
            WriteFixedString(b.AsSpan(92, 64), m.Subaddress);
            return b;
        }

        static byte[] EncodeOcrp(OutgoingCallReply m)
        {
            // CallID(2) PeerCallID(2) ResultCode(1) ErrorCode(1) CauseCode(2) ConnectSpeed(4)
            // RecvWindow(2) ProcessingDelay(2) PhysicalChannelID(4)
            byte[] b = new byte[2 + 2 + 1 + 1 + 2 + 4 + 2 + 2 + 4];
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(0, 2), m.CallId);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2, 2), m.PeerCallId);
            b[4] = (byte)m.ResultCode;
            b[5] = m.ErrorCode;
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(6, 2), m.CauseCode);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(8, 4), m.ConnectSpeed);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(12, 2), m.PacketRecvWindowSize);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(14, 2), m.PacketProcessingDelay);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(16, 4), m.PhysicalChannelId);
            return b;
        }

        static byte[] EncodeSetLinkInfo(SetLinkInfo m)
        {
            // PeerCallID(2) Reserved1(2) SendACCM(4) ReceiveACCM(4)
            byte[] b = new byte[2 + 2 + 4 + 4];
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(0, 2), m.PeerCallId);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4, 4), m.SendAccm);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(8, 4), m.ReceiveAccm);
            return b;
        }

        static byte[] EncodeCallClear(CallClearRequest m)
        {
            // CallID(2) Reserved1(2)
            byte[] b = new byte[4];
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(0, 2), m.CallId);
            return b;
        }

        static byte[] EncodeCdn(CallDisconnectNotify m)
        {
            // CallID(2) ResultCode(1) ErrorCode(1) CauseCode(2) Reserved1(2) CallStatistics(128)
            byte[] b = new byte[2 + 1 + 1 + 2 + 2 + CallDisconnectNotify.CallStatisticsLength];
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(0, 2), m.CallId);
            b[2] = (byte)m.ResultCode;
            b[3] = m.ErrorCode;
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(4, 2), m.CauseCode);
            WriteFixedString(b.AsSpan(8, CallDisconnectNotify.CallStatisticsLength), m.CallStatistics);
            return b;
        }

        // ---------------- Body decoders ----------------

        static IPptpControlMessage DecodeBody(PptpControlMessageType type, ReadOnlySpan<byte> body) => type switch
        {
            PptpControlMessageType.StartControlConnectionRequest => DecodeSccrq(body),
            PptpControlMessageType.StartControlConnectionReply => DecodeSccrp(body),
            PptpControlMessageType.StopControlConnectionRequest => DecodeStopRequest(body),
            PptpControlMessageType.StopControlConnectionReply => DecodeStopReply(body),
            PptpControlMessageType.EchoRequest => DecodeEchoRequest(body),
            PptpControlMessageType.EchoReply => DecodeEchoReply(body),
            PptpControlMessageType.OutgoingCallRequest => DecodeOcrq(body),
            PptpControlMessageType.OutgoingCallReply => DecodeOcrp(body),
            PptpControlMessageType.SetLinkInfo => DecodeSetLinkInfo(body),
            PptpControlMessageType.CallClearRequest => DecodeCallClear(body),
            PptpControlMessageType.CallDisconnectNotify => DecodeCdn(body),
            _ => throw new FormatException($"Unsupported PPTP control message type {(ushort)type}."),
        };

        static StartControlConnectionRequest DecodeSccrq(ReadOnlySpan<byte> b)
        {
            Require(b, 144, "Start-Control-Connection-Request");
            return new StartControlConnectionRequest
            {
                ProtocolVersion = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(0, 2)),
                FramingCapabilities = (PptpFramingCapability)BinaryPrimitives.ReadUInt32BigEndian(b.Slice(4, 4)),
                BearerCapabilities = (PptpBearerCapability)BinaryPrimitives.ReadUInt32BigEndian(b.Slice(8, 4)),
                MaximumChannels = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(12, 2)),
                FirmwareRevision = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(14, 2)),
                HostName = ReadFixedString(b.Slice(16, 64)),
                VendorName = ReadFixedString(b.Slice(80, 64)),
            };
        }

        static StartControlConnectionReply DecodeSccrp(ReadOnlySpan<byte> b)
        {
            Require(b, 144, "Start-Control-Connection-Reply");
            return new StartControlConnectionReply
            {
                ProtocolVersion = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(0, 2)),
                ResultCode = (PptpResultCode)b[2],
                ErrorCode = b[3],
                FramingCapabilities = (PptpFramingCapability)BinaryPrimitives.ReadUInt32BigEndian(b.Slice(4, 4)),
                BearerCapabilities = (PptpBearerCapability)BinaryPrimitives.ReadUInt32BigEndian(b.Slice(8, 4)),
                MaximumChannels = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(12, 2)),
                FirmwareRevision = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(14, 2)),
                HostName = ReadFixedString(b.Slice(16, 64)),
                VendorName = ReadFixedString(b.Slice(80, 64)),
            };
        }

        static StopControlConnectionRequest DecodeStopRequest(ReadOnlySpan<byte> b)
        {
            Require(b, 4, "Stop-Control-Connection-Request");
            return new StopControlConnectionRequest { Reason = b[0] };
        }

        static StopControlConnectionReply DecodeStopReply(ReadOnlySpan<byte> b)
        {
            Require(b, 4, "Stop-Control-Connection-Reply");
            return new StopControlConnectionReply { ResultCode = (PptpResultCode)b[0], ErrorCode = b[1] };
        }

        static EchoRequest DecodeEchoRequest(ReadOnlySpan<byte> b)
        {
            Require(b, 4, "Echo-Request");
            return new EchoRequest { Identifier = BinaryPrimitives.ReadUInt32BigEndian(b.Slice(0, 4)) };
        }

        static EchoReply DecodeEchoReply(ReadOnlySpan<byte> b)
        {
            Require(b, 8, "Echo-Reply");
            return new EchoReply
            {
                Identifier = BinaryPrimitives.ReadUInt32BigEndian(b.Slice(0, 4)),
                ResultCode = (PptpResultCode)b[4],
                ErrorCode = b[5],
            };
        }

        static OutgoingCallRequest DecodeOcrq(ReadOnlySpan<byte> b)
        {
            Require(b, 156, "Outgoing-Call-Request");
            return new OutgoingCallRequest
            {
                CallId = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(0, 2)),
                CallSerialNumber = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(2, 2)),
                MinBps = BinaryPrimitives.ReadUInt32BigEndian(b.Slice(4, 4)),
                MaxBps = BinaryPrimitives.ReadUInt32BigEndian(b.Slice(8, 4)),
                BearerType = BinaryPrimitives.ReadUInt32BigEndian(b.Slice(12, 4)),
                FramingType = BinaryPrimitives.ReadUInt32BigEndian(b.Slice(16, 4)),
                PacketRecvWindowSize = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(20, 2)),
                PacketProcessingDelay = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(22, 2)),
                // bytes 24..25 = PhoneNumberLength, 26..27 = Reserved1
                PhoneNumber = ReadFixedString(b.Slice(28, 64)),
                Subaddress = ReadFixedString(b.Slice(92, 64)),
            };
        }

        static OutgoingCallReply DecodeOcrp(ReadOnlySpan<byte> b)
        {
            Require(b, 20, "Outgoing-Call-Reply");
            return new OutgoingCallReply
            {
                CallId = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(0, 2)),
                PeerCallId = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(2, 2)),
                ResultCode = (PptpResultCode)b[4],
                ErrorCode = b[5],
                CauseCode = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(6, 2)),
                ConnectSpeed = BinaryPrimitives.ReadUInt32BigEndian(b.Slice(8, 4)),
                PacketRecvWindowSize = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(12, 2)),
                PacketProcessingDelay = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(14, 2)),
                PhysicalChannelId = BinaryPrimitives.ReadUInt32BigEndian(b.Slice(16, 4)),
            };
        }

        static SetLinkInfo DecodeSetLinkInfo(ReadOnlySpan<byte> b)
        {
            Require(b, 12, "Set-Link-Info");
            return new SetLinkInfo
            {
                PeerCallId = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(0, 2)),
                SendAccm = BinaryPrimitives.ReadUInt32BigEndian(b.Slice(4, 4)),
                ReceiveAccm = BinaryPrimitives.ReadUInt32BigEndian(b.Slice(8, 4)),
            };
        }

        static CallClearRequest DecodeCallClear(ReadOnlySpan<byte> b)
        {
            Require(b, 4, "Call-Clear-Request");
            return new CallClearRequest { CallId = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(0, 2)) };
        }

        static CallDisconnectNotify DecodeCdn(ReadOnlySpan<byte> b)
        {
            Require(b, 8 + CallDisconnectNotify.CallStatisticsLength, "Call-Disconnect-Notify");
            return new CallDisconnectNotify
            {
                CallId = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(0, 2)),
                ResultCode = (PptpResultCode)b[2],
                ErrorCode = b[3],
                CauseCode = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(4, 2)),
                CallStatistics = ReadFixedString(b.Slice(8, CallDisconnectNotify.CallStatisticsLength)),
            };
        }

        // ---------------- Helpers ----------------

        static void Require(ReadOnlySpan<byte> body, int min, string name)
        {
            if (body.Length < min)
                throw new FormatException($"PPTP {name} body too short ({body.Length} < {min} bytes).");
        }

        // Writes an ASCII string into a fixed-length field, NUL-padded; truncates if longer than the field.
        static void WriteFixedString(Span<byte> field, string? value)
        {
            field.Clear();
            if (string.IsNullOrEmpty(value)) return;
            byte[] ascii = Encoding.ASCII.GetBytes(value);
            int n = System.Math.Min(ascii.Length, field.Length);
            ascii.AsSpan(0, n).CopyTo(field);
        }

        // Reads an ASCII string out of a fixed-length field, stopping at the first NUL.
        static string ReadFixedString(ReadOnlySpan<byte> field)
        {
            int end = field.IndexOf((byte)0);
            if (end < 0) end = field.Length;
            return Encoding.ASCII.GetString(field.Slice(0, end).ToArray());
        }
    }
}
