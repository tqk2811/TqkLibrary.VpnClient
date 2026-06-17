using System.Net;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Models
{
    /// <summary>
    /// Describes a successful auto-reconnect. ocserv usually re-assigns the same tunnel address to a returning session
    /// (the auth cookie is reused), but it may differ, so the new address and a changed flag are carried for parity with
    /// the OpenVPN/IKEv2 reconnect info (a changed address means in-tunnel sockets must be re-established).
    /// </summary>
    public sealed class OpenConnectReconnectInfo
    {
        /// <summary>Creates the info for a completed reconnect.</summary>
        public OpenConnectReconnectInfo(IPAddress newAddress, bool addressChanged)
        {
            NewAddress = newAddress ?? IPAddress.Any;
            AddressChanged = addressChanged;
        }

        /// <summary>The tunnel address after the reconnect.</summary>
        public IPAddress NewAddress { get; }

        /// <summary>True when the re-assigned address differs from the previous one (in-tunnel sockets break).</summary>
        public bool AddressChanged { get; }
    }
}
