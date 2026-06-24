using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Ppp.Enums;
using TqkLibrary.VpnClient.Ppp.Models;

namespace TqkLibrary.VpnClient.Ppp
{
    /// <summary>
    /// IPV6CP negotiator (RFC 5072). As a client it requests an 8-byte Interface-Identifier and adopts whatever the
    /// server forces back via Configure-Nak; as a server it assigns the peer an Interface-Identifier by Nak'ing a
    /// zero / colliding value (mirrors <see cref="IpcpNegotiator"/>). The negotiated identifier yields the link-local
    /// address fe80::/64 + IID. Only the Interface-Identifier option is supported; IPv6-Compression is rejected.
    /// </summary>
    public sealed class Ipv6cpNegotiator : PppNegotiator
    {
        byte[] _localInterfaceId;
        readonly byte[]? _assignPeerInterfaceId;

        /// <summary>
        /// Creates an IPV6CP negotiator. <paramref name="localInterfaceId"/> is the 8-byte identifier we request for
        /// ourselves. If <paramref name="assignPeerInterfaceId"/> is set we act as a server and force it onto the peer.
        /// </summary>
        public Ipv6cpNegotiator(Action<byte[]> send, byte[] localInterfaceId, byte[]? assignPeerInterfaceId = null,
            ILogger? logger = null)
            : base(send, layer: "ppp.ipv6cp", logger: logger)
        {
            if (localInterfaceId == null || localInterfaceId.Length != 8)
                throw new ArgumentException("The IPV6CP Interface-Identifier must be exactly 8 bytes.", nameof(localInterfaceId));
            if (assignPeerInterfaceId != null && assignPeerInterfaceId.Length != 8)
                throw new ArgumentException("The assigned peer Interface-Identifier must be exactly 8 bytes.", nameof(assignPeerInterfaceId));

            _localInterfaceId = (byte[])localInterfaceId.Clone();
            _assignPeerInterfaceId = assignPeerInterfaceId == null ? null : (byte[])assignPeerInterfaceId.Clone();
        }

        /// <summary>Our negotiated Interface-Identifier (8 bytes; may change after a server Nak).</summary>
        public byte[] InterfaceId => (byte[])_localInterfaceId.Clone();

        /// <summary>Our link-local IPv6 address (fe80::/64 + the negotiated Interface-Identifier).</summary>
        public IPAddress LinkLocalAddress => BuildLinkLocal(_localInterfaceId);

        bool IsServer => _assignPeerInterfaceId != null;

        /// <inheritdoc/>
        protected override IReadOnlyList<PppOption> BuildLocalOptions()
            => new[] { new PppOption((byte)Ipv6cpOptionType.InterfaceIdentifier, (byte[])_localInterfaceId.Clone()) };

        /// <inheritdoc/>
        protected override (byte code, IReadOnlyList<PppOption> options) EvaluatePeerRequest(List<PppOption> peerOptions)
        {
            var rejected = new List<PppOption>();
            var naks = new List<PppOption>();
            foreach (PppOption option in peerOptions)
            {
                if (option.Type != (byte)Ipv6cpOptionType.InterfaceIdentifier)
                {
                    rejected.Add(option); // only Interface-Identifier is supported (no compression)
                    continue;
                }
                byte[]? suggestion = EvaluatePeerInterfaceId(option.Data);
                if (suggestion != null)
                    naks.Add(new PppOption(option.Type, suggestion));
            }

            if (rejected.Count > 0) return ((byte)PppCode.ConfigureReject, rejected); // Reject precedes Nak (RFC 1661 §4)
            if (naks.Count > 0) return ((byte)PppCode.ConfigureNak, naks);
            return ((byte)PppCode.ConfigureAck, peerOptions);
        }

        // Returns an Interface-Identifier to Nak the peer with, or null to accept the peer's request.
        byte[]? EvaluatePeerInterfaceId(byte[] peerId)
        {
            if (IsServer)
                return ByteArrayEquals(peerId, _assignPeerInterfaceId!) ? null : (byte[])_assignPeerInterfaceId!.Clone();

            // Client: the only illegal values are all-zero (RFC 5072 §4.1) or a collision with our own identifier.
            if (peerId.Length == 8 && !IsZero(peerId) && !ByteArrayEquals(peerId, _localInterfaceId))
                return null; // accept the peer's identifier
            return Alternative(peerId);
        }

        /// <inheritdoc/>
        protected override void OnNak(List<PppOption> nakOptions)
        {
            foreach (PppOption option in nakOptions)
                if (option.Type == (byte)Ipv6cpOptionType.InterfaceIdentifier && option.Data.Length == 8)
                    _localInterfaceId = (byte[])option.Data.Clone();
        }

        static IPAddress BuildLinkLocal(byte[] interfaceId)
        {
            byte[] addr = new byte[16];
            addr[0] = 0xFE;
            addr[1] = 0x80; // fe80::/64
            Buffer.BlockCopy(interfaceId, 0, addr, 8, 8);
            return new IPAddress(addr);
        }

        // A deterministic non-zero identifier distinct from the peer's (flip the U/L bit, force a non-zero tail).
        static byte[] Alternative(byte[] id)
        {
            byte[] alt = id.Length == 8 ? (byte[])id.Clone() : new byte[8];
            alt[0] ^= 0x02;
            alt[7] |= 0x01;
            return alt;
        }

        static bool IsZero(byte[] b)
        {
            foreach (byte x in b)
                if (x != 0) return false;
            return true;
        }

        static bool ByteArrayEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }
    }
}
