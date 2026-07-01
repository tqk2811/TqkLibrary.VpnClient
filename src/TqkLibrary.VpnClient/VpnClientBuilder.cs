using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.CiscoIpsec;
using TqkLibrary.VpnClient.Drivers.GreInUdp;
using TqkLibrary.VpnClient.Drivers.Ikev2;
using TqkLibrary.VpnClient.Drivers.IpEncap;
using TqkLibrary.VpnClient.Drivers.L2tpIpsec;
using TqkLibrary.VpnClient.Drivers.L2tpIpsec.Enums;
using TqkLibrary.VpnClient.Drivers.N2n;
using TqkLibrary.VpnClient.Drivers.N2n.Config;
using TqkLibrary.VpnClient.Drivers.Nebula;
using TqkLibrary.VpnClient.Drivers.Nebula.Config;
using TqkLibrary.VpnClient.Drivers.OpenConnect;
using TqkLibrary.VpnClient.Drivers.OpenVpn;
using TqkLibrary.VpnClient.Drivers.Pptp;
using TqkLibrary.VpnClient.Drivers.SoftEther;
using TqkLibrary.VpnClient.Drivers.Sstp;
using TqkLibrary.VpnClient.Drivers.Tailscale;
using TqkLibrary.VpnClient.Drivers.Tailscale.Config;
using TqkLibrary.VpnClient.Drivers.Ssh;
using TqkLibrary.VpnClient.Drivers.Ssh.Config;
using TqkLibrary.VpnClient.Drivers.Tinc;
using TqkLibrary.VpnClient.Drivers.Tinc.Config;
using TqkLibrary.VpnClient.Drivers.Vtun;
using TqkLibrary.VpnClient.Drivers.Vtun.Config;
using TqkLibrary.VpnClient.Drivers.Vxlan;
using TqkLibrary.VpnClient.Drivers.Vxlan.Config;
using TqkLibrary.VpnClient.Drivers.WireGuard;
using TqkLibrary.VpnClient.Drivers.ZeroTier;
using TqkLibrary.VpnClient.Drivers.ZeroTier.Config;
using TqkLibrary.VpnClient.OpenVpn.Config;
using TqkLibrary.VpnClient.SoftEther.Models;
using TqkLibrary.VpnClient.WireGuard.Config;

namespace TqkLibrary.VpnClient
{
    /// <summary>Fluent builder that registers protocol drivers and produces a <see cref="VpnClient"/>.</summary>
    public sealed class VpnClientBuilder
    {
        readonly Dictionary<string, IVpnProtocolDriver> _drivers = new();

        /// <summary>Registers a driver (keyed by its <see cref="IVpnProtocolDriver.Name"/>).</summary>
        public VpnClientBuilder AddDriver(IVpnProtocolDriver driver)
        {
            _drivers[driver.Name] = driver;
            return this;
        }

        /// <summary>Registers the MS-SSTP driver with auto-reconnect enabled by default.</summary>
        public VpnClientBuilder UseSstp() => AddDriver(new SstpDriver());

        /// <summary>Registers the MS-SSTP driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseSstp(SstpReconnectOptions reconnectOptions) => AddDriver(new SstpDriver(reconnectOptions));

        /// <summary>Registers the MS-SSTP driver with a TLS server-certificate validation callback (default behavior accepts any cert).</summary>
        public VpnClientBuilder UseSstp(RemoteCertificateValidationCallback certificateValidationCallback)
            => AddDriver(new SstpDriver(certificateValidationCallback: certificateValidationCallback));

        /// <summary>Registers the MS-SSTP driver with explicit auto-reconnect options and a TLS server-certificate validation callback.</summary>
        public VpnClientBuilder UseSstp(SstpReconnectOptions reconnectOptions, RemoteCertificateValidationCallback certificateValidationCallback)
            => AddDriver(new SstpDriver(reconnectOptions, certificateValidationCallback));

        /// <summary>Registers the L2TP/IPsec driver (IKEv1 PSK + NAT-T) with auto-reconnect enabled by default.</summary>
        public VpnClientBuilder UseL2tpIpsec() => AddDriver(new L2tpIpsecDriver());

        /// <summary>Registers the L2TP/IPsec driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseL2tpIpsec(L2tpIpsecReconnectOptions reconnectOptions) => AddDriver(new L2tpIpsecDriver(reconnectOptions));

        /// <summary>Registers the L2TP/IPsec driver with explicit auto-reconnect and IKE/L2TP timeout options.</summary>
        public VpnClientBuilder UseL2tpIpsec(L2tpIpsecReconnectOptions reconnectOptions, L2tpIpsecTimeoutOptions timeoutOptions)
            => AddDriver(new L2tpIpsecDriver(reconnectOptions, timeoutOptions));

        /// <summary>
        /// Registers the L2TP/IPsec driver with a raw-IP transport factory, enabling the <b>native ESP (proto-50)</b>
        /// carrier for a no-NAT gateway under <see cref="L2tpIpsecNatTraversalMode.HonestFirst"/> (the default for this
        /// overload). Requires elevation; pass <c>new RawIpTransportFactory()</c> from <c>TqkLibrary.VpnClient.Transport.RawIp</c>.
        /// </summary>
        public VpnClientBuilder UseL2tpIpsec(IRawIpTransportFactory rawIpFactory,
            L2tpIpsecNatTraversalMode natTraversalMode = L2tpIpsecNatTraversalMode.HonestFirst,
            L2tpIpsecReconnectOptions? reconnectOptions = null, L2tpIpsecTimeoutOptions? timeoutOptions = null)
            => AddDriver(new L2tpIpsecDriver(reconnectOptions, timeoutOptions, natTraversalMode, rawIpFactory: rawIpFactory));

        /// <summary>
        /// Registers the PPTP driver (RFC 2637): a TCP/1723 control connection, a GRE (proto-47) data plane, MPPE
        /// (RFC 3078/3079) and PPP/MS-CHAPv2. The GRE data plane needs <paramref name="rawIpFactory"/> (raw IP
        /// proto-47 — requires elevation; pass <c>new RawIpTransportFactory()</c> from
        /// <c>TqkLibrary.VpnClient.Transport.RawIp</c>). <paramref name="reconnectOptions"/> tunes (or disables)
        /// auto-reconnect; <paramref name="timeoutOptions"/> tunes the handshake timeout and Echo keepalive interval.
        /// <para><b>PPTP + MS-CHAPv2 + MPPE/RC4 is legacy and cryptographically insecure</b> — interop only; prefer
        /// L2TP/IPsec, IKEv2, OpenVPN or WireGuard for any new deployment.</para>
        /// </summary>
        public VpnClientBuilder UsePptp(IRawIpTransportFactory rawIpFactory,
            PptpReconnectOptions? reconnectOptions = null, PptpTimeoutOptions? timeoutOptions = null)
            => AddDriver(new PptpDriver(rawIpFactory, reconnectOptions, timeoutOptions));

        /// <summary>
        /// Registers the plain IP-in-IP / GRE tunnel driver (RFC 2784/2890 GRE proto-47, RFC 2003 IPIP proto-4,
        /// RFC 4213 SIT/6in4 proto-41): opens a raw-IP transport on the kind's protocol number and binds the matching
        /// data-plane channel behind a stable L3 packet channel. <paramref name="rawIpFactory"/> carries the data plane
        /// (a raw IP socket on the kind's protocol number — requires elevation; pass <c>new RawIpTransportFactory()</c>
        /// from <c>TqkLibrary.VpnClient.Transport.RawIp</c>). <paramref name="options"/> selects the encap kind / MTU /
        /// GRE options (default GRE); <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect.
        /// <para>There is no control plane (no handshake, no auth, no keepalive) — the tunnel address must be arranged
        /// out of band. <b>GRE/IPIP/SIT are UNENCRYPTED</b> — use only on a trusted path or under IPsec ESP.</para>
        /// </summary>
        public VpnClientBuilder UseIpEncap(IRawIpTransportFactory rawIpFactory, IpEncapOptions? options = null,
            IpEncapReconnectOptions? reconnectOptions = null)
            => AddDriver(new IpEncapDriver(rawIpFactory, options, reconnectOptions));

        /// <summary>
        /// Registers the GRE-in-UDP tunnel driver (RFC 8086): carries a standard GRE header (RFC 2784/2890) inside a UDP
        /// payload on dst port 4754 instead of raw-IP proto-47, then binds the reused GRE data-plane channel behind a
        /// stable L3 packet channel. Because the carrier is an ordinary connected UDP socket, it needs <b>no elevation
        /// and no raw IP socket</b> and traverses NAT/firewalls that pass UDP. <paramref name="options"/> selects the
        /// UDP port / MTU / GRE options (default port 4754); <paramref name="reconnectOptions"/> tunes (or disables)
        /// auto-reconnect. The remote gateway is the <c>VpnEndpoint.Host</c> passed to <c>ConnectAsync</c>.
        /// <para>There is no control plane (no handshake, no auth, no keepalive) — the tunnel address must be arranged
        /// out of band. <b>GRE-in-UDP is UNENCRYPTED</b> — use only on a trusted path or under IPsec ESP.</para>
        /// </summary>
        public VpnClientBuilder UseGreInUdp(GreInUdpOptions? options = null, GreInUdpReconnectOptions? reconnectOptions = null)
            => AddDriver(new GreInUdpDriver(options, reconnectOptions));

        /// <summary>Registers the IKEv2-native driver (RFC 7296 PSK + NAT-T, CP virtual IP, ESP tunnel mode) with auto-reconnect enabled by default.</summary>
        public VpnClientBuilder UseIkev2() => AddDriver(new Ikev2Driver());

        /// <summary>Registers the IKEv2-native driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseIkev2(Ikev2ReconnectOptions reconnectOptions) => AddDriver(new Ikev2Driver(reconnectOptions));

        /// <summary>
        /// Registers the IKEv2-native driver that verifies the gateway by <b>certificate</b> (RFC 7296 §2.15 digital
        /// signature): the responder's CERT must be trusted by <paramref name="responderTrust"/> and its AUTH signature
        /// must verify, otherwise the connection is refused. Auto-reconnect is enabled by default unless
        /// <paramref name="reconnectOptions"/> says otherwise.
        /// </summary>
        public VpnClientBuilder UseIkev2(Ipsec.Ike.V2.Models.IkeCertificateTrust responderTrust,
            Ikev2ReconnectOptions? reconnectOptions = null)
            => AddDriver(new Ikev2Driver(reconnectOptions, responderTrust: responderTrust));

        /// <summary>
        /// Registers the Cisco IPsec / EzVPN remote-access driver for the Aggressive Mode group <paramref name="groupName"/>:
        /// IKEv1 Aggressive Mode (group PSK from <c>VpnCredentials.PreSharedKey</c>) + XAUTH (<c>Username</c>/<c>Password</c>)
        /// + Mode-Config (pulls the virtual IP/DNS) over forced NAT-T, then an ESP tunnel-mode CHILD SA straight to the IP
        /// channel — no PPP/L2TP. Auto-reconnect is enabled by default unless <paramref name="reconnectOptions"/> disables it.
        /// <para><b>Security:</b> Aggressive Mode + group PSK is cryptographically weak (offline dictionary attack on the
        /// group PSK from the responder's HASH_R) — interop with legacy Cisco-compatible gateways only; prefer IKEv2 or
        /// L2TP/IPsec Main Mode where available.</para>
        /// </summary>
        public VpnClientBuilder UseCiscoIpsec(string groupName, CiscoIpsecReconnectOptions? reconnectOptions = null)
            => AddDriver(new CiscoIpsecDriver(groupName, reconnectOptions));

        /// <summary>Registers the OpenVPN driver (community-server compatible: UDP/TCP, tun-mode, NCP AEAD) from a parsed profile.</summary>
        public VpnClientBuilder UseOpenVpn(OpenVpnProfile profile) => AddDriver(new OpenVpnDriver(profile));

        /// <summary>Registers the OpenVPN driver with client certificates and an optional server-certificate validation callback.</summary>
        public VpnClientBuilder UseOpenVpn(OpenVpnProfile profile, X509CertificateCollection? clientCertificates,
            RemoteCertificateValidationCallback? serverCertificateValidation = null, OpenVpnReconnectOptions? reconnectOptions = null)
            => AddDriver(new OpenVpnDriver(profile, clientCertificates, serverCertificateValidation, reconnectOptions: reconnectOptions));

        /// <summary>
        /// Registers the OpenVPN driver with IPv6 in the tunnel enabled (tap-mode only): besides the IPv4 ifconfig/DHCP
        /// lease + ARP, the tap bridge also runs SLAAC/DHCPv6 + NDISC v6 over the same L2 segment (best-effort — an
        /// IPv4-only bridge still connects; no effect on tun-mode).
        /// </summary>
        public VpnClientBuilder UseOpenVpn(OpenVpnProfile profile, bool enableIpv6)
            => AddDriver(new OpenVpnDriver(profile, enableIpv6: enableIpv6));

        /// <summary>Registers the WireGuard driver (UDP, Noise_IKpsk2, static point-to-point config) with auto-reconnect enabled by default.</summary>
        public VpnClientBuilder UseWireGuard(WireGuardConfig config) => AddDriver(new WireGuardDriver(config));

        /// <summary>Registers the WireGuard driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseWireGuard(WireGuardConfig config, WireGuardReconnectOptions reconnectOptions)
            => AddDriver(new WireGuardDriver(config, reconnectOptions));

        /// <summary>
        /// Registers the Nebula (Slack mesh VPN) driver: a UDP transport, the Noise_IX_25519_AESGCM_SHA256 handshake
        /// (certificate auth against the network CA) and a type-1 (Message) AES-256-GCM data plane behind a stable L3
        /// packet channel. The static <see cref="NebulaConfig"/> (CA cert, host cert + X25519 key, peer endpoint, overlay
        /// IP/CIDR, MTU) maps straight to a <c>TunnelConfig</c> (no IPCP/DHCP). Auto-reconnect is enabled by default.
        /// </summary>
        public VpnClientBuilder UseNebula(NebulaConfig config) => AddDriver(new NebulaDriver(config));

        /// <summary>Registers the Nebula driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseNebula(NebulaConfig config, NebulaReconnectOptions reconnectOptions)
            => AddDriver(new NebulaDriver(config, reconnectOptions));

        /// <summary>
        /// Registers the Tailscale driver: the ts2021 control plane (a Noise IK handshake to a Headscale/Tailscale
        /// coordination server, a preauth-key node registration and a netmap fetch over HTTP/2) projected onto a
        /// multi-peer WireGuard config, with the WireGuard data plane reused wholesale (Noise_IKpsk2 + type-4 transport +
        /// crypto-routing). The static <see cref="TailscaleConfig"/> (server URL, preauth key, machine/node X25519 keys,
        /// MTU) drives the control plane; the overlay address and routes come from the netmap
        /// (<c>AddressAssignment.OutOfBand</c>). DERP relay + disco NAT traversal are future work (peers must be directly
        /// reachable). Auto-reconnect is enabled by default.
        /// </summary>
        public VpnClientBuilder UseTailscale(TailscaleConfig config) => AddDriver(new TailscaleDriver(config));

        /// <summary>Registers the Tailscale driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseTailscale(TailscaleConfig config, TailscaleReconnectOptions reconnectOptions)
            => AddDriver(new TailscaleDriver(config, reconnectOptions));

        /// <summary>
        /// Registers the tinc 1.1 (SPTPS) driver: a TCP meta-connection (ID + Curve25519/Ed25519/ChaCha-Poly1305 SPTPS
        /// handshake, ACK, ADD_SUBNET/ADD_EDGE), a per-tunnel data-plane SPTPS session (REQ_KEY/ANS_KEY over the meta-
        /// connection) and a bare-IP (router-mode) data plane over UDP datagrams behind a stable L3 packet channel. The
        /// static <see cref="TincConfig"/> (this node's Ed25519 key + name, the peer host file, the overlay IP/CIDR, MTU)
        /// maps straight to a <c>TunnelConfig</c> (no IPCP/DHCP). Point-to-point to one peer. Auto-reconnect on by default.
        /// </summary>
        public VpnClientBuilder UseTinc(TincConfig config) => AddDriver(new TincDriver(config));

        /// <summary>Registers the tinc driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseTinc(TincConfig config, TincReconnectOptions reconnectOptions)
            => AddDriver(new TincDriver(config, reconnectOptions));

        /// <summary>
        /// Registers the n2n v3 (ntop) driver: a UDP transport to the supernode that registers the edge (REGISTER_SUPER /
        /// REGISTER_SUPER_ACK) and then carries full Ethernet frames as PACKET messages (NULL or AES-CBC transform)
        /// behind an L2 channel bridged into the Ethernet fabric (ARP + VirtualHost) down to a stable L3 packet channel.
        /// The static <see cref="N2nConfig"/> (community, this edge's static overlay IP + MAC, transform key, MTU) maps
        /// straight to a <c>TunnelConfig</c> (no DHCP); a keepalive REGISTER timer keeps the edge registered. Supernode-
        /// relayed point-to-point (P2P hole-punching bypassed). Auto-reconnect is enabled by default.
        /// </summary>
        public VpnClientBuilder UseN2n(N2nConfig config) => AddDriver(new N2nDriver(config));

        /// <summary>Registers the n2n driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseN2n(N2nConfig config, N2nReconnectOptions reconnectOptions)
            => AddDriver(new N2nDriver(config, reconnectOptions));

        /// <summary>
        /// Registers the vtun (legacy tunnel daemon) driver: a single TCP connection to one vtund host that runs the
        /// challenge-response authentication (50-byte ASCII message blocks, an MD5-keyed Blowfish-ECB challenge,
        /// server-dictated host flags) and then carries bare IP packets as length-prefixed data frames behind a stable L3
        /// packet channel, with a VTUN_ECHO keepalive. The static <see cref="VtunConfig"/> (host name + password, this
        /// client's static tunnel IP + peer, MTU) maps straight to a <c>TunnelConfig</c> (vtun does no in-tunnel address
        /// negotiation). Point-to-point, <c>type tun</c> over <c>proto tcp</c> with <c>encrypt no</c> + <c>compress no</c>.
        /// Auto-reconnect is enabled by default. ⚠️ vtun's crypto is legacy/weak — interop only.
        /// </summary>
        public VpnClientBuilder UseVtun(VtunConfig config) => AddDriver(new VtunDriver(config));

        /// <summary>Registers the vtun driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseVtun(VtunConfig config, VtunReconnectOptions reconnectOptions)
            => AddDriver(new VtunDriver(config, reconnectOptions));

        /// <summary>
        /// Registers the VPN-over-SSH (OpenSSH <c>-w</c> tun) driver: one TCP connection to an OpenSSH server that runs
        /// the SSH-2 transport handshake (version exchange, curve25519-sha256 KEX, ed25519 host-key verification,
        /// chacha20-poly1305@openssh.com / aes256-gcm@openssh.com), authenticates with the publickey (ed25519) or password
        /// method and opens a <c>tun@openssh.com</c> point-to-point (layer-3) channel, then carries bare IP packets behind
        /// a stable L3 packet channel. The static <see cref="SshConfig"/> (host/port/user, an Ed25519 key or password,
        /// this client's static tunnel IP + peer, MTU) maps straight to a <c>TunnelConfig</c> (SSH does no in-tunnel
        /// address negotiation). The client needs no elevation; the server needs <c>PermitTunnel</c> + a tun device.
        /// Auto-reconnect is enabled by default.
        /// </summary>
        public VpnClientBuilder UseSsh(SshConfig config) => AddDriver(new SshDriver(config));

        /// <summary>Registers the VPN-over-SSH driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseSsh(SshConfig config, SshReconnectOptions reconnectOptions)
            => AddDriver(new SshDriver(config, reconnectOptions));

        /// <summary>
        /// Registers the ZeroTier (VL1/VL2) driver: a UDP transport to a node/controller that runs the VL1
        /// <c>HELLO ⇄ OK</c> handshake (Curve25519 identity agreement → Salsa20/12 + Poly1305 session), joins a VL2
        /// network by asking the controller for its configuration (<c>NETWORK_CONFIG_REQUEST</c> → assigned IP +
        /// certificate of membership), then carries full Ethernet frames as VL2 <c>EXT_FRAME</c> messages behind an L2
        /// channel bridged into the Ethernet fabric (ARP + VirtualHost) down to a stable L3 packet channel. The static
        /// <see cref="ZeroTierConfig"/> (this node's identity, the peer node/controller's identity, the network id, the
        /// optional static overlay IP) maps to a <c>TunnelConfig</c> (controller-assigned or pinned address); an ECHO
        /// keepalive holds the path open. Planet/moon root discovery is bypassed (peer with the node/controller directly).
        /// Auto-reconnect is enabled by default.
        /// </summary>
        public VpnClientBuilder UseZeroTier(ZeroTierConfig config) => AddDriver(new ZeroTierDriver(config));

        /// <summary>Registers the ZeroTier driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseZeroTier(ZeroTierConfig config, ZeroTierReconnectOptions reconnectOptions)
            => AddDriver(new ZeroTierDriver(config, reconnectOptions));

        /// <summary>
        /// Registers the OpenConnect (Cisco AnyConnect / ocserv) driver: HTTPS config-auth then CSTP, in-band
        /// X-CSTP-* address, bare IP (no PPP), X-CSTP-DPD dead-peer-detection. The data plane runs over DTLS 1.2 when the
        /// gateway advertises X-DTLS-*, falling back to CSTP-over-TLS otherwise.
        /// </summary>
        public VpnClientBuilder UseOpenConnect() => AddDriver(new OpenConnectDriver());

        /// <summary>Registers the OpenConnect driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseOpenConnect(OpenConnectReconnectOptions reconnectOptions)
            => AddDriver(new OpenConnectDriver(reconnectOptions));

        /// <summary>
        /// Registers the OpenConnect driver with explicit auto-reconnect options, a TLS gateway-certificate validation
        /// callback (null = accept any cert), and an optional ocserv auth group selector.
        /// </summary>
        public VpnClientBuilder UseOpenConnect(OpenConnectReconnectOptions reconnectOptions,
            System.Net.Security.RemoteCertificateValidationCallback? certificateValidationCallback, string groupSelect = "")
            => AddDriver(new OpenConnectDriver(reconnectOptions, serverCertificateValidation: certificateValidationCallback, groupSelect: groupSelect));

        /// <summary>
        /// Registers the SoftEther SSL-VPN driver targeting <paramref name="hubName"/> (Ethernet-over-TLS, DHCP-leased
        /// address, SHA-0 password auth via the connect-time credentials) with auto-reconnect enabled by default.
        /// </summary>
        public VpnClientBuilder UseSoftEther(string hubName) => AddDriver(new SoftEtherDriver(hubName));

        /// <summary>Registers the SoftEther driver with explicit session params (parallel connections, encrypt/compress flags).</summary>
        public VpnClientBuilder UseSoftEther(string hubName, SoftEtherSessionParams session)
            => AddDriver(new SoftEtherDriver(hubName, session));

        /// <summary>Registers the SoftEther driver with explicit session params and auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseSoftEther(string hubName, SoftEtherSessionParams session, SoftEtherReconnectOptions reconnectOptions)
            => AddDriver(new SoftEtherDriver(hubName, session, reconnectOptions));

        /// <summary>
        /// Registers the SoftEther driver with IPv6 in the tunnel enabled: besides the IPv4 DHCP lease + ARP, the bridge
        /// also runs SLAAC/DHCPv6 + NDISC v6 over SecureNAT (best-effort — an IPv4-only server still connects).
        /// </summary>
        public VpnClientBuilder UseSoftEther(string hubName, bool enableIpv6)
            => AddDriver(new SoftEtherDriver(hubName, enableIpv6: enableIpv6));

        /// <summary>
        /// Registers the VXLAN (RFC 7348) driver: L2-over-UDP that carries full Ethernet frames behind an 8-byte VXLAN
        /// header over UDP/4789 to a static unicast remote VTEP, plugged into the Ethernet fabric (ARP + VirtualHost) down
        /// to a stable L3 packet channel — like n2n but with <b>no control plane</b> (no registration, keepalive,
        /// transform or encryption). The static <see cref="VxlanConfig"/> (VNI, this endpoint's static overlay IP + MAC,
        /// MTU) maps straight to a <c>TunnelConfig</c> (no DHCP); the remote VTEP host comes from the connect-time
        /// endpoint. No elevation required. Auto-reconnect is enabled by default.
        /// </summary>
        public VpnClientBuilder UseVxlan(VxlanConfig config) => AddDriver(new VxlanDriver(config));

        /// <summary>Registers the VXLAN driver with explicit auto-reconnect options (e.g. to disable it).</summary>
        public VpnClientBuilder UseVxlan(VxlanConfig config, VxlanReconnectOptions reconnectOptions)
            => AddDriver(new VxlanDriver(config, reconnectOptions));

        /// <summary>Builds the client.</summary>
        public VpnClient Build() => new VpnClient(_drivers);
    }
}
