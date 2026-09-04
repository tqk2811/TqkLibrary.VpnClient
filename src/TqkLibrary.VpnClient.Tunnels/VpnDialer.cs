using System.Net;
using System.Net.Sockets;
using System.Text;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Drivers.Ikev2;
using TqkLibrary.VpnClient.Drivers.L2tpIpsec;
using TqkLibrary.VpnClient.Drivers.OpenVpn;
using TqkLibrary.VpnClient.Drivers.SoftEther;
using TqkLibrary.VpnClient.Drivers.Sstp;
using TqkLibrary.VpnClient.Drivers.WireGuard;
using TqkLibrary.VpnClient.Drivers.WireGuard.Transport;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.OpenVpn.Config;
using TqkLibrary.VpnClient.SoftEther;
using TqkLibrary.VpnClient.WireGuard.Config;

namespace TqkLibrary.VpnClient.Tunnels
{
    /// <summary>
    /// Dials one VPN and hands back a live <see cref="VpnTunnel"/>. One method per protocol; adding a
    /// protocol is a driver ProjectReference and another method here.
    /// </summary>
    /// <remarks>
    /// The protocols do not take the same arguments, and this does not pretend otherwise: two of them
    /// are handed the file the provider gave you, the other four a server plus credentials, because
    /// no standard client configuration file exists for those. What every method does share is the
    /// shape of the result — connect, wrap the session's packet channel in a
    /// <see cref="TcpIpStack"/>, and hand back a handle that owns the teardown.
    /// </remarks>
    public static class VpnDialer
    {
        /// <summary>MS-SSTP over TLS: the tunnel VPN Gate's "SSTP" servers speak.</summary>
        public static async Task<VpnTunnel> ConnectSstpAsync(
            string host, int port, string user, string pass,
            VpnTunnelOptions? options = null, CancellationToken cancellationToken = default)
        {
            VpnTunnelOptions o = VpnTunnelOptions.OrDefault(options);
            var vpn = new SstpConnection(host, port,
                addressFamilyPreference: OuterPreference(o),
                enableIpv6: o.EnableIpv6,
                loggerFactory: o.LoggerFactory);
            try
            {
                using CancellationTokenSource cts = Deadline(o, cancellationToken);
                await vpn.ConnectAsync(user, pass, cts.Token).ConfigureAwait(false);

                IPAddress? v6 = GlobalV6(vpn.AssignedAddressV6);
                var stack = new TcpIpStack(vpn.PacketChannel, vpn.AssignedAddress, v6);
                return new VpnTunnel(vpn, stack, () => { vpn.Dispose(); return default; },
                    vpn.AssignedAddress, vpn.PacketChannel.Mtu, new SstpDriver().Name, vpn.AssignedDns, v6);
            }
            catch
            {
                vpn.Dispose();
                throw;
            }
        }

        /// <summary>L2TP inside IPsec (IKEv1 with a group pre-shared key, NAT-T).</summary>
        public static async Task<VpnTunnel> ConnectL2tpIpsecAsync(
            string host, string user, string pass, string preSharedKey,
            VpnTunnelOptions? options = null, CancellationToken cancellationToken = default)
        {
            VpnTunnelOptions o = VpnTunnelOptions.OrDefault(options);
            var vpn = new L2tpIpsecConnection(host, Encoding.ASCII.GetBytes(preSharedKey ?? string.Empty),
                addressFamilyPreference: OuterPreference(o),
                enableIpv6: o.EnableIpv6,
                loggerFactory: o.LoggerFactory);
            try
            {
                using CancellationTokenSource cts = Deadline(o, cancellationToken);
                await vpn.ConnectAsync(user, pass, cts.Token).ConfigureAwait(false);

                IPAddress? v6 = GlobalV6(vpn.AssignedAddressV6);
                var stack = new TcpIpStack(vpn.PacketChannel, vpn.AssignedAddress, v6);
                return new VpnTunnel(vpn, stack, async () => await vpn.DisposeAsync().ConfigureAwait(false),
                    vpn.AssignedAddress, vpn.PacketChannel.Mtu, new L2tpIpsecDriver().Name, vpn.AssignedDns, v6);
            }
            catch
            {
                await vpn.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// IKEv2 with ESP straight into the stack — no PPP. Authenticates with the group pre-shared
        /// key alone, or with EAP-MSCHAPv2 when a user name and password are supplied as well.
        /// </summary>
        public static async Task<VpnTunnel> ConnectIkev2Async(
            string host, string preSharedKey, string? eapUser, string? eapPass,
            VpnTunnelOptions? options = null, CancellationToken cancellationToken = default)
        {
            VpnTunnelOptions o = VpnTunnelOptions.OrDefault(options);
            var vpn = new Ikev2Connection(host, Encoding.ASCII.GetBytes(preSharedKey ?? string.Empty),
                addressFamilyPreference: OuterPreference(o),
                eapUserName: string.IsNullOrEmpty(eapUser) ? null : eapUser,
                eapPassword: string.IsNullOrEmpty(eapPass) ? null : eapPass,
                loggerFactory: o.LoggerFactory);
            try
            {
                using CancellationTokenSource cts = Deadline(o, cancellationToken);
                await vpn.ConnectAsync(cts.Token).ConfigureAwait(false);

                // The IKEv2 driver assigns IPv4 only, so the stack is built single-stack here.
                var stack = new TcpIpStack(vpn.PacketChannel, vpn.AssignedAddress, null);
                return new VpnTunnel(vpn, stack, async () => await vpn.DisposeAsync().ConfigureAwait(false),
                    vpn.AssignedAddress, vpn.PacketChannel.Mtu, new Ikev2Driver().Name, vpn.AssignedDns);
            }
            catch
            {
                await vpn.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// SoftEther SSL-VPN. Without a genuine watermark blob
        /// (<see cref="VpnTunnelOptions.SoftEtherWatermarkPath"/>) a real server answers HTTP 403 —
        /// the blob is GPL data and is not shipped here.
        /// </summary>
        public static async Task<VpnTunnel> ConnectSoftEtherAsync(
            string host, int port, string user, string pass, string hub,
            VpnTunnelOptions? options = null, CancellationToken cancellationToken = default)
        {
            VpnTunnelOptions o = VpnTunnelOptions.OrDefault(options);

            SoftEtherWatermark? watermark = null;
            if (!string.IsNullOrWhiteSpace(o.SoftEtherWatermarkPath))
                watermark = new SoftEtherWatermark().WithSignature(File.ReadAllBytes(o.SoftEtherWatermarkPath!));

            var driver = new SoftEtherDriver(hub, watermark: watermark,
                enableIpv6: o.EnableIpv6, loggerFactory: o.LoggerFactory);

            using CancellationTokenSource cts = Deadline(o, cancellationToken);
            IVpnConnection connection = await driver.ConnectAsync(
                new VpnEndpoint(host, port),
                new VpnCredentials { Username = user, Password = pass },
                cts.Token).ConfigureAwait(false);

            return Wrap(connection, ((SoftEtherVpnConnection)connection).Connection, driver.Name);
        }

        /// <summary>Connects from a <c>.ovpn</c> profile: its first <c>remote</c> is the endpoint.</summary>
        public static async Task<VpnTunnel> ConnectOpenVpnAsync(
            string configPath, string? user, string? pass,
            VpnTunnelOptions? options = null, CancellationToken cancellationToken = default)
        {
            VpnTunnelOptions o = VpnTunnelOptions.OrDefault(options);
            OpenVpnProfile profile = OpenVpnConfigParser.Parse(File.ReadAllText(configPath));
            if (profile.Remotes.Count == 0)
                throw new InvalidDataException($"The .ovpn profile '{configPath}' has no 'remote <host> <port>' line.");

            OpenVpnRemote remote = profile.Remotes[0];
            var driver = new OpenVpnDriver(profile, enableIpv6: o.EnableIpv6, loggerFactory: o.LoggerFactory);

            using CancellationTokenSource cts = Deadline(o, cancellationToken);
            IVpnConnection connection = await driver.ConnectAsync(
                new VpnEndpoint(remote.Host, remote.Port),
                new VpnCredentials
                {
                    Username = string.IsNullOrEmpty(user) ? null : user,
                    Password = string.IsNullOrEmpty(pass) ? null : pass,
                },
                cts.Token).ConfigureAwait(false);

            return Wrap(connection, ((OpenVpnVpnConnection)connection).Connection, driver.Name);
        }

        /// <summary>
        /// Connects to a WireGuard peer from a wg-quick <c>.conf</c>, in this process. No TUN adapter
        /// and no route table: the tunnel exists only as the stack this returns.
        /// </summary>
        public static async Task<VpnTunnel> ConnectWireGuardAsync(
            string configPath,
            VpnTunnelOptions? options = null, CancellationToken cancellationToken = default)
        {
            VpnTunnelOptions o = VpnTunnelOptions.OrDefault(options);
            (WireGuardConfig config, string host, int port) = WireGuardConfFile.Load(configPath);

            var vpn = new WireGuardConnection(host, port, config, new WireGuardSocketTransportFactory(),
                addressFamilyPreference: OuterPreference(o),
                loggerFactory: o.LoggerFactory);
            try
            {
                using CancellationTokenSource cts = Deadline(o, cancellationToken);
                await vpn.ConnectAsync(cts.Token).ConfigureAwait(false);

                IPAddress assigned = vpn.AssignedAddress ?? IPAddress.Any;
                IPAddress? dns = vpn.Config.DnsServers.Count > 0 ? vpn.Config.DnsServers[0] : null;
                IPAddress? v6 = GlobalV6(vpn.Config.AssignedAddressV6);
                var stack = new TcpIpStack(vpn.PacketChannel, assigned, v6);
                return new VpnTunnel(vpn, stack, async () => await vpn.DisposeAsync().ConfigureAwait(false),
                    assigned, vpn.PacketChannel.Mtu, new WireGuardDriver(config).Name, dns, v6);
            }
            catch
            {
                await vpn.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        // The two driver-façade protocols land here: take the primary session's channel and address,
        // and let the IVpnConnection wrapper own the teardown of everything below it.
        static VpnTunnel Wrap(IVpnConnection connection, Drivers.Core.ReconnectingVpnConnection inner, string protocolName)
        {
            try
            {
                IVpnSession session = connection.Sessions[0];
                IPAddress assigned = session.Config.AssignedAddress ?? IPAddress.Any;
                IPAddress? dns = session.Config.DnsServers.Count > 0 ? session.Config.DnsServers[0] : null;
                IPAddress? v6 = GlobalV6(session.Config.AssignedAddressV6);

                var stack = new TcpIpStack(session.PacketChannel, assigned, v6);
                return new VpnTunnel(inner, stack,
                    async () => await connection.DisposeAsync().ConfigureAwait(false),
                    assigned, session.PacketChannel.Mtu, protocolName, dns, v6);
            }
            catch
            {
                _ = connection.DisposeAsync();
                throw;
            }
        }

        static CancellationTokenSource Deadline(VpnTunnelOptions options, CancellationToken cancellationToken)
        {
            CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(options.ConnectTimeout);
            return cts;
        }

        static AddressFamilyPreference OuterPreference(VpnTunnelOptions options)
            => options.PreferOuterIpv6 ? AddressFamilyPreference.IPv6 : AddressFamilyPreference.Auto;

        // Only a GLOBAL IPv6 routes to the internet. Many servers hand out a link-local address and
        // nothing else; treating that as IPv6 support would advertise a route that cannot carry
        // anything, so it is read as "no IPv6" and the stack stays IPv4-only.
        static IPAddress? GlobalV6(IPAddress? address)
            => address is not null
               && address.AddressFamily == AddressFamily.InterNetworkV6
               && !address.IsIPv6LinkLocal
                ? address
                : null;
    }
}
