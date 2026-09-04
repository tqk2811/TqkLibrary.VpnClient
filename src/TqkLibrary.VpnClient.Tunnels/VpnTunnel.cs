using System.Net;
using TqkLibrary.VpnClient.Drivers.Core;
using TqkLibrary.VpnClient.Drivers.Core.Enums;
using TqkLibrary.VpnClient.IpStack;

namespace TqkLibrary.VpnClient.Tunnels
{
    /// <summary>
    /// A VPN tunnel that is up, exposed as a userspace <see cref="TcpIpStack"/> so an application can
    /// open connections inside it.
    /// </summary>
    /// <remarks>
    /// The stack alone would not do: it is bound to the live VPN connection underneath, and that
    /// connection has to outlive every socket opened on it. This handle owns the teardown, and it
    /// also republishes the driver's own supervision — <see cref="State"/> and
    /// <see cref="StateChanged"/> come straight from <see cref="ReconnectingVpnConnection"/>, which
    /// re-establishes a dropped link by itself. A host holding the tunnel open should watch those
    /// rather than build its own health check: rebuilding the tunnel while the driver is already
    /// mending it only fights the driver.
    /// </remarks>
    public sealed class VpnTunnel : IAsyncDisposable
    {
        readonly ReconnectingVpnConnection _connection;
        readonly Func<ValueTask> _disposeAsync;
        int _disposed;

        internal VpnTunnel(
            ReconnectingVpnConnection connection,
            TcpIpStack stack,
            Func<ValueTask> disposeAsync,
            IPAddress assignedAddress,
            int mtu,
            string protocolName,
            IPAddress? assignedDns = null,
            IPAddress? assignedAddressV6 = null)
        {
            _connection = connection ?? throw new ArgumentNullException(nameof(connection));
            Stack = stack ?? throw new ArgumentNullException(nameof(stack));
            _disposeAsync = disposeAsync ?? throw new ArgumentNullException(nameof(disposeAsync));
            AssignedAddress = assignedAddress ?? throw new ArgumentNullException(nameof(assignedAddress));
            Mtu = mtu;
            ProtocolName = protocolName ?? throw new ArgumentNullException(nameof(protocolName));
            AssignedDns = assignedDns;
            AssignedAddressV6 = assignedAddressV6;

            _connection.StateChanged += OnStateChanged;
        }

        /// <summary>The userspace TCP/IP stack running inside the tunnel.</summary>
        public TcpIpStack Stack { get; }

        /// <summary>The IPv4 address the VPN assigned.</summary>
        public IPAddress AssignedAddress { get; }

        /// <summary>
        /// The GLOBAL IPv6 the tunnel assigned, or null when the server offered none (or only a
        /// link-local one, which cannot reach the internet). Non-null means the stack is dual-stack.
        /// </summary>
        public IPAddress? AssignedAddressV6 { get; }

        /// <summary>
        /// The DNS server the VPN handed out, if any. Resolving through this — over the tunnel's own
        /// UDP socket — is what keeps name lookups from leaking to the machine's resolver.
        /// </summary>
        public IPAddress? AssignedDns { get; }

        /// <summary>The tunnel link's MTU.</summary>
        public int Mtu { get; }

        /// <summary>The driver's name, for logs ("sstp", "l2tp-ipsec", …).</summary>
        public string ProtocolName { get; }

        /// <summary>Where the driver's own supervision currently is.</summary>
        public VpnConnectionState State => _connection.State;

        /// <summary>True while the tunnel is carrying traffic.</summary>
        public bool IsUp => _connection.State == VpnConnectionState.Connected;

        /// <summary>
        /// Raised on the driver's supervision thread whenever <see cref="State"/> changes. A handler
        /// must not block it. <see cref="VpnConnectionState.Disconnected"/> after a
        /// <see cref="VpnConnectionState.Reconnecting"/> is the driver giving up: the tunnel is dead
        /// and only a new one will do.
        /// </summary>
        public event Action<VpnConnectionState>? StateChanged;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            _connection.StateChanged -= OnStateChanged;
            await _disposeAsync().ConfigureAwait(false);
        }

        void OnStateChanged(VpnConnectionState state)
        {
            try { StateChanged?.Invoke(state); }
            catch { /* a broken subscriber must not take down the driver's supervisor */ }
        }
    }
}
