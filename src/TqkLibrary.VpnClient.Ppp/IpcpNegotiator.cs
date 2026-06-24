using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Ppp.Enums;
using TqkLibrary.VpnClient.Ppp.Models;

namespace TqkLibrary.VpnClient.Ppp
{
    /// <summary>
    /// IPCP negotiator (RFC 1332 + RFC 1877). As a client it requests an IP-Address (0.0.0.0) and DNS, then
    /// adopts whatever the server returns via Configure-Nak. As a server it assigns the peer an address by
    /// Nak'ing the peer's request.
    /// </summary>
    public sealed class IpcpNegotiator : PppNegotiator
    {
        IPAddress _localAddress;
        IPAddress _dns = IPAddress.Any;
        readonly IPAddress? _assignPeerAddress;
        readonly IPAddress? _assignPeerDns;

        /// <summary>
        /// Creates an IPCP negotiator. <paramref name="localAddress"/> is the address we request for ourselves
        /// (0.0.0.0 for a client). If <paramref name="assignPeerAddress"/> is set we act as a server and assign it.
        /// </summary>
        public IpcpNegotiator(Action<byte[]> send, IPAddress localAddress, IPAddress? assignPeerAddress = null, IPAddress? assignPeerDns = null,
            ILogger? logger = null)
            : base(send, layer: "ppp.ipcp", logger: logger)
        {
            _localAddress = localAddress;
            _assignPeerAddress = assignPeerAddress;
            _assignPeerDns = assignPeerDns;
        }

        /// <summary>Our negotiated IP address (after any server Nak).</summary>
        public IPAddress AssignedAddress => _localAddress;

        /// <summary>The DNS server learned via IPCP, or null if none.</summary>
        public IPAddress? AssignedDns => _dns.Equals(IPAddress.Any) ? null : _dns;

        bool IsServer => _assignPeerAddress != null;

        /// <inheritdoc/>
        protected override IReadOnlyList<PppOption> BuildLocalOptions()
        {
            var options = new List<PppOption>
            {
                new PppOption((byte)IpcpOptionType.IpAddress, _localAddress.GetAddressBytes()),
            };
            if (!IsServer)
                options.Add(new PppOption((byte)IpcpOptionType.PrimaryDns, _dns.GetAddressBytes()));
            return options;
        }

        /// <inheritdoc/>
        protected override (byte code, IReadOnlyList<PppOption> options) EvaluatePeerRequest(List<PppOption> peerOptions)
        {
            if (!IsServer)
                return ((byte)PppCode.ConfigureAck, peerOptions); // client accepts the server's gateway address

            // Server: assign the peer its address (and DNS) by Nak'ing zero / mismatched values.
            var naks = new List<PppOption>();
            foreach (PppOption option in peerOptions)
            {
                if (option.Type == (byte)IpcpOptionType.IpAddress)
                {
                    var requested = new IPAddress(option.Data);
                    if (!requested.Equals(_assignPeerAddress))
                        naks.Add(new PppOption(option.Type, _assignPeerAddress!.GetAddressBytes()));
                }
                else if (option.Type == (byte)IpcpOptionType.PrimaryDns && _assignPeerDns != null)
                {
                    var requested = new IPAddress(option.Data);
                    if (!requested.Equals(_assignPeerDns))
                        naks.Add(new PppOption(option.Type, _assignPeerDns.GetAddressBytes()));
                }
            }

            return naks.Count > 0
                ? ((byte)PppCode.ConfigureNak, naks)
                : ((byte)PppCode.ConfigureAck, peerOptions);
        }

        /// <inheritdoc/>
        protected override void OnNak(List<PppOption> nakOptions)
        {
            foreach (PppOption option in nakOptions)
            {
                if (option.Type == (byte)IpcpOptionType.IpAddress && option.Data.Length == 4)
                    _localAddress = new IPAddress(option.Data);
                else if (option.Type == (byte)IpcpOptionType.PrimaryDns && option.Data.Length == 4)
                    _dns = new IPAddress(option.Data);
            }
        }
    }
}
