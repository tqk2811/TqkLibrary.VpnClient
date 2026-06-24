using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.CiscoIpsec;
using TqkLibrary.VpnClient.Drivers.Ikev2;
using TqkLibrary.VpnClient.Drivers.IpEncap;
using TqkLibrary.VpnClient.Drivers.L2tpIpsec;
using TqkLibrary.VpnClient.Drivers.L2tpIpsec.Enums;
using TqkLibrary.VpnClient.Drivers.Nebula;
using TqkLibrary.VpnClient.Drivers.Nebula.Config;
using TqkLibrary.VpnClient.Drivers.OpenConnect;
using TqkLibrary.VpnClient.Drivers.OpenVpn;
using TqkLibrary.VpnClient.Drivers.Pptp;
using TqkLibrary.VpnClient.Drivers.SoftEther;
using TqkLibrary.VpnClient.Drivers.Sstp;
using TqkLibrary.VpnClient.Drivers.Tinc;
using TqkLibrary.VpnClient.Drivers.Tinc.Config;
using TqkLibrary.VpnClient.Drivers.WireGuard;
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

        /// <summary>Builds the client.</summary>
        public VpnClient Build() => new VpnClient(_drivers);
    }
}
