using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Ethernet.Models;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// Composes an <see cref="EthernetSwitch"/> with N <see cref="VirtualHost"/>s into a multi-host userspace LAN
    /// (design 09: the <c>EthernetAdapter</c> = IPacketChannel-provider). Each host is described by an
    /// <see cref="EthernetHostSpec"/> — {<see cref="INeighborResolver"/> (ARP/NDISC), optional
    /// <see cref="IAddressConfigurator"/> (DHCPv4/SLAAC+DHCPv6), inbound-seam hooks} built over the host's freshly
    /// connected switch port — and surfaces its own backpressured <see cref="IPacketChannel"/> through
    /// <see cref="EthernetHostHandle.Channel"/>, the stable façade a userspace IP stack binds to.
    /// <para>
    /// This is the assembly layer an L2 driver (SoftEther, OpenVPN-tap) uses to expose a multi-host broadcast domain
    /// instead of hand-wiring a single <see cref="VirtualHost"/> + <see cref="ArpResolver"/>. It performs the exact seam
    /// wiring those drivers do today (<c>host.InboundNonIpFrame += arp.HandleInboundFrame</c>;
    /// <c>host.InboundIpPacket += dhcp/ndisc.HandleInboundFrame</c>) and adds a per-host inbound queue + read-loop so a
    /// slow stack cannot stall the synchronous in-memory switch fabric (design 09 §"Hiệu năng").
    /// </para>
    /// </summary>
    public sealed partial class EthernetAdapter : IAsyncDisposable
    {
        readonly EthernetSwitch _switch;
        readonly bool _ownsSwitch;
        readonly EthernetAdapterOptions _options;
        readonly object _sync = new object();
        readonly Dictionary<MacAddress, EthernetHostHandle> _hosts = new Dictionary<MacAddress, EthernetHostHandle>();
        bool _disposed;

        /// <summary>Creates an adapter over a freshly created <see cref="EthernetSwitch"/> (which it owns and disposes).</summary>
        public EthernetAdapter(EthernetAdapterOptions? options = null)
            : this(new EthernetSwitch((options ?? EthernetAdapterOptions.Default).SwitchMtu), ownsSwitch: true, options)
        {
        }

        /// <summary>
        /// Creates an adapter over an existing <paramref name="ethernetSwitch"/> (e.g. one already bridged onto a VPN
        /// uplink). When <paramref name="ownsSwitch"/> is <c>true</c> the adapter disposes the switch on
        /// <see cref="DisposeAsync"/>; otherwise the caller owns it.
        /// </summary>
        public EthernetAdapter(EthernetSwitch ethernetSwitch, bool ownsSwitch = false, EthernetAdapterOptions? options = null)
        {
            _switch = ethernetSwitch ?? throw new ArgumentNullException(nameof(ethernetSwitch));
            _ownsSwitch = ownsSwitch;
            _options = options ?? EthernetAdapterOptions.Default;
        }

        /// <summary>The underlying learning switch — exposed so an L2 driver can attach its own uplink port.</summary>
        public EthernetSwitch Switch => _switch;

        /// <summary>Number of virtual hosts currently attached.</summary>
        public int HostCount
        {
            get { lock (_sync) return _hosts.Count; }
        }

        /// <summary>
        /// Attaches a virtual host with MAC <paramref name="mac"/>: connects its switch port, lets <paramref name="build"/>
        /// build the resolver/configurator/seam-hooks over that port, builds the <see cref="VirtualHost"/> bridge, wires
        /// the inbound seams, wraps it in a backpressured <see cref="IPacketChannel"/>, and returns the handle whose
        /// <see cref="EthernetHostHandle.Channel"/> a userspace stack binds to.
        /// <para>
        /// <paramref name="build"/> receives the freshly connected <see cref="IEthernetChannel"/> port so the
        /// resolver/configurator can share it (they send ARP/DHCP out the same port the host uses), mirroring the manual
        /// composition in <c>SoftEtherConnection</c> / <c>OpenVpnConnection</c>.
        /// </para>
        /// </summary>
        /// <exception cref="ArgumentException">A host with the same MAC is already attached.</exception>
        public EthernetHostHandle AddHost(MacAddress mac, Func<IEthernetChannel, EthernetHostSpec> build)
        {
            if (build is null)
                throw new ArgumentNullException(nameof(build));

            lock (_sync)
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(EthernetAdapter));
                if (_hosts.ContainsKey(mac))
                    throw new ArgumentException($"A host with MAC {mac} is already attached.", nameof(mac));
            }

            // Mirror the manual composition used by SoftEther/OpenVPN-tap drivers, now done once here.
            IEthernetChannel port = _switch.ConnectHost(mac);
            EthernetHostSpec spec;
            VirtualHost host;
            BackpressuredPacketChannel channel;
            try
            {
                spec = build(port) ?? throw new InvalidOperationException("The host build callback returned null.");
                host = new VirtualHost(mac, port, spec.Resolver);
                if (spec.NonIpFrameHandler != null)
                    host.InboundNonIpFrame += spec.NonIpFrameHandler;   // ARP rides the non-IP seam
                if (spec.IpPacketHandler != null)
                    host.InboundIpPacket += spec.IpPacketHandler;       // NDISC / DHCP ride inside ordinary IP
                channel = new BackpressuredPacketChannel(host, _options.InboundQueueCapacity, _options.InboundFullMode);
            }
            catch
            {
                _ = port.DisposeAsync();   // building failed → detach the port so the switch is not left with a stray
                throw;
            }

            var handle = new EthernetHostHandle(mac, host, channel, spec);
            lock (_sync)
            {
                if (_disposed)
                {
                    // Lost the race against DisposeAsync — clean up the just-built host instead of leaking it.
                    _ = handle.DisposeAsync();
                    throw new ObjectDisposedException(nameof(EthernetAdapter));
                }
                _hosts.Add(mac, handle);
            }
            return handle;
        }

        /// <summary>Returns the handle for the host with <paramref name="mac"/>, or <c>null</c> if none is attached.</summary>
        public EthernetHostHandle? GetHost(MacAddress mac)
        {
            lock (_sync)
                return _hosts.TryGetValue(mac, out EthernetHostHandle? handle) ? handle : null;
        }

        /// <summary>
        /// Detaches and disposes the host with <paramref name="mac"/> (no-op if none). Returns <c>true</c> if a host was
        /// removed.
        /// </summary>
        public async ValueTask<bool> RemoveHostAsync(MacAddress mac)
        {
            EthernetHostHandle? handle;
            lock (_sync)
            {
                if (!_hosts.TryGetValue(mac, out handle))
                    return false;
                _hosts.Remove(mac);
            }
            await handle.DisposeAsync().ConfigureAwait(false);
            return true;
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            EthernetHostHandle[] hosts;
            lock (_sync)
            {
                if (_disposed)
                    return;
                _disposed = true;
                hosts = new EthernetHostHandle[_hosts.Count];
                _hosts.Values.CopyTo(hosts, 0);
                _hosts.Clear();
            }

            foreach (EthernetHostHandle handle in hosts)
            {
                try { await handle.DisposeAsync().ConfigureAwait(false); }
                catch { /* tear down the rest regardless */ }
            }

            if (_ownsSwitch)
                await _switch.DisposeAsync().ConfigureAwait(false);
        }
    }
}
