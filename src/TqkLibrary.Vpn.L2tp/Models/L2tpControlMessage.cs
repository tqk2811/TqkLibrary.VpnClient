using TqkLibrary.Vpn.L2tp.Enums;

namespace TqkLibrary.Vpn.L2tp.Models
{
    /// <summary>
    /// An L2TPv2 control message: the addressing/sequence fields from the header plus its AVP list. A message with
    /// no AVPs is a ZLB (zero-length body) acknowledgement used purely to advance the reliable channel.
    /// </summary>
    public sealed class L2tpControlMessage
    {
        /// <summary>The tunnel id the recipient assigned (0 before the peer's Assigned Tunnel ID is known).</summary>
        public ushort TunnelId { get; set; }

        /// <summary>The session id the recipient assigned (0 for tunnel-level messages).</summary>
        public ushort SessionId { get; set; }

        /// <summary>Send sequence number Ns.</summary>
        public ushort Ns { get; set; }

        /// <summary>Receive sequence number Nr (next expected peer Ns).</summary>
        public ushort Nr { get; set; }

        /// <summary>The message type (ignored for a ZLB).</summary>
        public L2tpMessageType MessageType { get; set; }

        /// <summary>True if this is an acknowledgement-only message (no AVPs).</summary>
        public bool IsZeroLengthBody { get; set; }

        /// <summary>The AVPs after the Message Type AVP.</summary>
        public List<L2tpAvp> Avps { get; } = new();

        /// <summary>Returns the first AVP of the given type, or null.</summary>
        public L2tpAvp? Find(L2tpAvpType type)
        {
            foreach (L2tpAvp avp in Avps)
                if (avp.Type == type) return avp;
            return null;
        }

        /// <summary>Creates a control message of the given type with no extra AVPs yet.</summary>
        public static L2tpControlMessage Create(L2tpMessageType type, ushort tunnelId)
            => new() { MessageType = type, TunnelId = tunnelId };

        /// <summary>Creates a ZLB acknowledgement addressed to <paramref name="tunnelId"/>.</summary>
        public static L2tpControlMessage Ack(ushort tunnelId)
            => new() { IsZeroLengthBody = true, TunnelId = tunnelId };

        /// <summary>Adds an AVP and returns this message for chaining.</summary>
        public L2tpControlMessage With(L2tpAvp avp)
        {
            Avps.Add(avp);
            return this;
        }
    }
}
