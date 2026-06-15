using System.Net;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Models
{
    /// <summary>Describes a successful auto-reconnect: the freshly pushed tunnel address and whether it changed.</summary>
    public sealed class OpenVpnReconnectInfo
    {
        /// <summary>Creates the info for a completed reconnect.</summary>
        public OpenVpnReconnectInfo(IPAddress assignedAddress, bool addressChanged)
        {
            AssignedAddress = assignedAddress;
            AddressChanged = addressChanged;
        }

        /// <summary>The tunnel IP address the server pushed (via PUSH_REPLY) on the new tunnel.</summary>
        public IPAddress AssignedAddress { get; }

        /// <summary>
        /// True if the new address differs from the previous one. When true, in-tunnel sockets bound to the old
        /// address are stale and the consumer must rebuild its IP stack; same-address reconnects keep working.
        /// </summary>
        public bool AddressChanged { get; }
    }
}
