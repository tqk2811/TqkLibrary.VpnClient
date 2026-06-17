using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.OpenConnect;
using TqkLibrary.VpnClient.OpenConnect.Models;
using Xunit;

namespace TqkLibrary.VpnClient.OpenConnect.Tests
{
    /// <summary>
    /// Tests the OpenConnect HTTP CONNECT codec (V5.a): building the CONNECT request and parsing the X-CSTP-* tunnel
    /// headers (incl. mapping onto <see cref="TunnelConfig"/>), plus rejecting a non-200 gateway response.
    /// </summary>
    public class OpenConnectConnectCodecTests
    {
        [Fact]
        public void BuildConnectRequest_HasConnectLineCookieAndMtu()
        {
            string req = OpenConnectConnectCodec.BuildConnectRequest("vpn.example.com", "webvpn=ABC123", 1406);
            Assert.StartsWith("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n", req);
            Assert.Contains("Host: vpn.example.com\r\n", req);
            Assert.Contains("Cookie: webvpn=ABC123\r\n", req);
            Assert.Contains("X-CSTP-Base-MTU: 1406\r\n", req);
            Assert.EndsWith("\r\n\r\n", req);
        }

        [Fact]
        public void BuildConnectRequest_WrapsRawCookieValue()
        {
            string req = OpenConnectConnectCodec.BuildConnectRequest("h", "RAWVALUE");
            Assert.Contains("Cookie: webvpn=RAWVALUE\r\n", req);
        }

        [Fact]
        public void ParseConnectResponse_ParsesAllCstpHeaders()
        {
            const string resp =
                "HTTP/1.1 200 CONNECTED\r\n" +
                "X-CSTP-Version: 1\r\n" +
                "X-CSTP-Address: 10.10.10.5\r\n" +
                "X-CSTP-Netmask: 255.255.255.0\r\n" +
                "X-CSTP-DNS: 8.8.8.8\r\n" +
                "X-CSTP-DNS: 1.1.1.1\r\n" +
                "X-CSTP-Split-Include: 192.168.0.0/16\r\n" +
                "X-CSTP-MTU: 1400\r\n" +
                "X-CSTP-DPD: 30\r\n" +
                "X-CSTP-Keepalive: 20\r\n" +
                "X-CSTP-Rekey-Method: ssl\r\n" +
                "X-CSTP-Rekey-Time: 3600\r\n" +
                "\r\n";

            OpenConnectTunnelInfo info = OpenConnectConnectCodec.ParseConnectResponse(resp);
            Assert.Equal(IPAddress.Parse("10.10.10.5"), info.Address);
            Assert.Equal(IPAddress.Parse("255.255.255.0"), info.Netmask);
            Assert.Equal(new[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse("1.1.1.1") }, info.DnsServers);
            Assert.Equal(new[] { "192.168.0.0/16" }, info.Routes);
            Assert.Equal(1400, info.Mtu);
            Assert.Equal(30, info.Dpd);
            Assert.Equal(20, info.Keepalive);
            Assert.Equal("ssl", info.RekeyMethod);
            Assert.Equal(3600, info.RekeyTime);

            TunnelConfig cfg = info.ToTunnelConfig();
            Assert.Equal(IPAddress.Parse("10.10.10.5"), cfg.AssignedAddress);
            Assert.Equal(24, cfg.PrefixLength);
            Assert.Equal(1400, cfg.Mtu);
            Assert.Equal(2, cfg.DnsServers.Count);
            Assert.Equal(new[] { "192.168.0.0/16" }, cfg.Routes);
        }

        [Fact]
        public void ParseConnectResponse_PrefersMtuOverBaseMtu()
        {
            const string resp =
                "HTTP/1.1 200 OK\r\n" +
                "X-CSTP-Base-MTU: 1280\r\n" +
                "X-CSTP-MTU: 1400\r\n" +
                "\r\n";
            Assert.Equal(1400, OpenConnectConnectCodec.ParseConnectResponse(resp).Mtu);
        }

        [Fact]
        public void ParseConnectResponse_FallsBackToBaseMtu()
        {
            const string resp = "HTTP/1.1 200 OK\r\nX-CSTP-Base-MTU: 1280\r\n\r\n";
            Assert.Equal(1280, OpenConnectConnectCodec.ParseConnectResponse(resp).Mtu);
        }

        [Fact]
        public void ParseConnectResponse_ParsesIPv6Address()
        {
            const string resp = "HTTP/1.1 200 OK\r\nX-CSTP-Address-IP6: 2001:db8::5/64\r\n\r\n";
            OpenConnectTunnelInfo info = OpenConnectConnectCodec.ParseConnectResponse(resp);
            Assert.Equal(IPAddress.Parse("2001:db8::5"), info.AddressV6);
            Assert.Equal(64, info.PrefixLengthV6);
            TunnelConfig cfg = info.ToTunnelConfig();
            Assert.Equal(IPAddress.Parse("2001:db8::5"), cfg.AssignedAddressV6);
        }

        [Fact]
        public void ParseConnectResponse_RejectsNon200()
        {
            const string resp = "HTTP/1.1 401 Unauthorized\r\nX-Reason: bad cookie\r\n\r\n";
            var ex = Assert.Throws<UnauthorizedAccessException>(() => OpenConnectConnectCodec.ParseConnectResponse(resp));
            Assert.Contains("401", ex.Message);
        }

        [Fact]
        public void ParseConnectResponse_RejectsMalformedStatusLine()
        {
            Assert.Throws<FormatException>(() => OpenConnectConnectCodec.ParseConnectResponse("GARBAGE\r\n\r\n"));
        }

        [Fact]
        public void ParseConnectResponse_ExtractsSetCookie()
        {
            const string resp = "HTTP/1.1 200 OK\r\nSet-Cookie: webvpn=NEWSESSION; Secure\r\n\r\n";
            Assert.Equal("webvpn=NEWSESSION", OpenConnectConnectCodec.ParseConnectResponse(resp).SessionCookie);
        }

        [Fact]
        public void BuildConnectRequest_RequiresHostAndCookie()
        {
            Assert.Throws<ArgumentException>(() => OpenConnectConnectCodec.BuildConnectRequest("", "c"));
            Assert.Throws<ArgumentException>(() => OpenConnectConnectCodec.BuildConnectRequest("h", ""));
        }

        [Fact]
        public void BuildConnectRequest_AdvertisesDtls_WhenRequested()
        {
            string req = OpenConnectConnectCodec.BuildConnectRequest("h", "c", 1400,
                requestDtls: true, dtlsMasterSecretHex: "deadbeef");
            Assert.Contains("X-DTLS-Master-Secret: deadbeef\r\n", req);
            Assert.Contains("X-DTLS-CipherSuite: ", req);

            // Without the flag the request advertises no DTLS headers (TLS-only).
            string noDtls = OpenConnectConnectCodec.BuildConnectRequest("h", "c", 1400);
            Assert.DoesNotContain("X-DTLS-", noDtls);
        }

        [Fact]
        public void ParseConnectResponse_ParsesDtlsHeaders()
        {
            const string resp =
                "HTTP/1.1 200 CONNECTED\r\n" +
                "X-CSTP-Address: 10.10.10.5\r\n" +
                "X-DTLS-Session-ID: 0123456789abcdef\r\n" +
                "X-DTLS-CipherSuite: AES256-GCM-SHA384\r\n" +
                "X-DTLS-Port: 4443\r\n" +
                "X-DTLS-DPD: 40\r\n" +
                "X-DTLS-Keepalive: 25\r\n" +
                "\r\n";

            OpenConnectTunnelInfo info = OpenConnectConnectCodec.ParseConnectResponse(resp);
            Assert.Equal("0123456789abcdef", info.DtlsSessionId);
            Assert.Equal("AES256-GCM-SHA384", info.DtlsCipherSuite);
            Assert.Equal(4443, info.DtlsPort);
            Assert.Equal(40, info.DtlsDpd);
            Assert.Equal(25, info.DtlsKeepalive);
            Assert.True(info.HasDtls);
        }

        [Fact]
        public void HasDtls_FalseWithoutSessionIdOrPort()
        {
            OpenConnectTunnelInfo noDtls = OpenConnectConnectCodec.ParseConnectResponse(
                "HTTP/1.1 200 OK\r\nX-CSTP-Address: 10.0.0.2\r\n\r\n");
            Assert.False(noDtls.HasDtls);

            // A session id but no usable port ⇒ still not a usable DTLS path.
            OpenConnectTunnelInfo noPort = OpenConnectConnectCodec.ParseConnectResponse(
                "HTTP/1.1 200 OK\r\nX-CSTP-Address: 10.0.0.2\r\nX-DTLS-Session-ID: abc\r\n\r\n");
            Assert.False(noPort.HasDtls);
        }
    }
}
