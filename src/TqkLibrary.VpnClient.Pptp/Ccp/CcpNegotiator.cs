using System.Collections.Generic;
using TqkLibrary.VpnClient.Crypto.Mppe.Enums;
using TqkLibrary.VpnClient.Ppp;
using TqkLibrary.VpnClient.Ppp.Enums;
using TqkLibrary.VpnClient.Ppp.Models;
using TqkLibrary.VpnClient.Pptp.Enums;

namespace TqkLibrary.VpnClient.Pptp.Ccp
{
    /// <summary>
    /// CCP (Compression Control Protocol, RFC 1962) negotiator that negotiates the single MPPE option
    /// (RFC 2118 §3 / RFC 3078 §3.1) it cares about, reusing the shared PPP option-negotiation state machine
    /// (<see cref="PppNegotiator"/>, the same one LCP/IPCP use). It offers the client's preferred strength +
    /// stateless flag, adopts the peer's Configure-Nak hint (a server typically Naks to pin one strength), and
    /// acks/Naks the peer's own request down to the strongest common encryption bit.
    /// <para>
    /// CCP rides PPP protocol 0x80FD; the negotiated MPPE protocol uses 0x00FD (Compressed) for data. Once
    /// <see cref="PppNegotiator.Opened"/> fires, <see cref="NegotiatedStrength"/> / <see cref="NegotiatedStateless"/>
    /// give the parameters for the <c>MppeSession</c> the data plane builds. <b>MPPE/RC4 is broken — legacy only.</b>
    /// </para>
    /// </summary>
    public sealed class CcpNegotiator : PppNegotiator
    {
        MppeConfigOption _local;
        readonly MppeKeyStrength _maxStrength;

        /// <summary>
        /// Creates a CCP negotiator that emits control packets through <paramref name="send"/> and offers
        /// <paramref name="preferredStrength"/> (default 128-bit) and <paramref name="stateless"/> (default false,
        /// i.e. stateful — what PPTP servers expect). <paramref name="preferredStrength"/> is also the strongest
        /// strength we will accept from the peer: a peer offer stronger than this is Naked down to it.
        /// </summary>
        public CcpNegotiator(Action<byte[]> send, MppeKeyStrength preferredStrength = MppeKeyStrength.Bits128, bool stateless = false)
            : base(send)
        {
            _local = new MppeConfigOption(preferredStrength, stateless);
            _maxStrength = preferredStrength;
        }

        /// <summary>The MPPE option we are currently offering (updated by Nak hints).</summary>
        public MppeConfigOption LocalOption => _local;

        /// <summary>The negotiated key strength (valid once <see cref="PppNegotiator.Opened"/> has fired).</summary>
        public MppeKeyStrength NegotiatedStrength => _local.Strength;

        /// <summary>Whether stateless mode was negotiated (valid once Opened).</summary>
        public bool NegotiatedStateless => _local.Stateless;

        /// <inheritdoc/>
        protected override IReadOnlyList<PppOption> BuildLocalOptions()
            => new[] { new PppOption(MppeConfigOption.OptionType, _local.EncodeValue()) };

        /// <inheritdoc/>
        protected override (byte code, IReadOnlyList<PppOption> options) EvaluatePeerRequest(List<PppOption> peerOptions)
        {
            var rejected = new List<PppOption>();
            var nak = new List<PppOption>();
            var ack = new List<PppOption>();

            foreach (PppOption option in peerOptions)
            {
                if (option.Type != MppeConfigOption.OptionType)
                {
                    rejected.Add(option); // we only understand the MPPE option
                    continue;
                }

                MppeConfigOption peer;
                try { peer = MppeConfigOption.DecodeValue(option.Data); }
                catch (FormatException) { rejected.Add(option); continue; }

                if (!peer.HasEncryption)
                {
                    // No encryption bit offered — Nak with our preferred strength.
                    nak.Add(new PppOption(MppeConfigOption.OptionType, _local.EncodeValue()));
                    continue;
                }

                // Cap the peer's offered strength to the strongest we accept, and (if it offered several bits)
                // pin it to a single bit. A peer strength above our maximum, or a multi-bit offer, gets Naked down.
                MppeKeyStrength capped = Rank(peer.Strength) > Rank(_maxStrength) ? _maxStrength : peer.Strength;
                var pinned = new MppeConfigOption(capped, peer.Stateless);
                if (pinned.Bits != peer.Bits)
                    nak.Add(new PppOption(MppeConfigOption.OptionType, pinned.EncodeValue()));
                else
                    ack.Add(option);
            }

            if (rejected.Count > 0) return ((byte)PppCode.ConfigureReject, rejected);
            if (nak.Count > 0) return ((byte)PppCode.ConfigureNak, nak);
            return ((byte)PppCode.ConfigureAck, ack);
        }

        /// <inheritdoc/>
        protected override void OnNak(List<PppOption> nakOptions)
        {
            foreach (PppOption option in nakOptions)
            {
                if (option.Type != MppeConfigOption.OptionType) continue;
                try
                {
                    MppeConfigOption hint = MppeConfigOption.DecodeValue(option.Data);
                    if (hint.HasEncryption)
                        _local = new MppeConfigOption(hint.Strength, hint.Stateless); // adopt the server's pinned value
                }
                catch (FormatException) { /* ignore malformed hint, keep our offer */ }
            }
        }

        /// <inheritdoc/>
        protected override void OnReject(List<PppOption> rejectedOptions)
        {
            // A peer that rejects the MPPE option outright leaves us with nothing to encrypt with; surface it.
            foreach (PppOption option in rejectedOptions)
                if (option.Type == MppeConfigOption.OptionType)
                    throw new NotSupportedException("Peer rejected the MPPE CCP option — encryption cannot be negotiated.");
        }

        // Orders the key strengths so we can compare "stronger than": 128 > 56 > 40.
        static int Rank(MppeKeyStrength strength) => strength switch
        {
            MppeKeyStrength.Bits128 => 3,
            MppeKeyStrength.Bits56 => 2,
            MppeKeyStrength.Bits40 => 1,
            _ => 0,
        };
    }
}
