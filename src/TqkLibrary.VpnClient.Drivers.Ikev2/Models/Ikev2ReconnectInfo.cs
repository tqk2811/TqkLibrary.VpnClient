using System.Net;

namespace TqkLibrary.VpnClient.Drivers.Ikev2.Models
{
    /// <summary>Describes a successful auto-reconnect: the freshly assigned virtual address and whether it changed.</summary>
    public sealed class Ikev2ReconnectInfo
    {
        /// <summary>Creates the info for a completed reconnect.</summary>
        public Ikev2ReconnectInfo(IPAddress assignedAddress, bool addressChanged)
        {
            AssignedAddress = assignedAddress;
            AddressChanged = addressChanged;
        }

        /// <summary>The virtual IP address the gateway assigned (via CFG_REPLY) on the new tunnel.</summary>
        public IPAddress AssignedAddress { get; }

        /// <summary>
        /// True if the new address differs from the previous one. When true, in-tunnel sockets bound to the old
        /// address are stale and the consumer must rebuild its IP stack; same-address reconnects keep working.
        /// </summary>
        public bool AddressChanged { get; }
    }
}
