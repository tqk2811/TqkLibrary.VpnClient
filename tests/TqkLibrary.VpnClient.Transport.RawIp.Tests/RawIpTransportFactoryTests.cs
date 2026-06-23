using System.Net;
using TqkLibrary.VpnClient.Transport.RawIp;
using TqkLibrary.VpnClient.Transport.RawIp.Exceptions;
using TqkLibrary.VpnClient.Transport.RawIp.Interfaces;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.RawIp.Tests
{
    /// <summary>
    /// Factory/privilege behaviour that can be observed without elevation. Opening a real raw socket needs admin/root
    /// (covered by the live lab, roadmap Q.1); here we pin that the API never throws on probe and that a denied open
    /// surfaces as <see cref="RawIpNotPermittedException"/> with privilege guidance.
    /// </summary>
    public class RawIpTransportFactoryTests
    {
        [Fact]
        public void IsAvailable_DoesNotThrow_AndReturnsBool()
        {
            var factory = new RawIpTransportFactory();
            _ = factory.IsAvailable; // a privilege probe must never throw, only report
        }

        [Fact]
        public void PrivilegeChecker_IsElevated_DoesNotThrow()
        {
            _ = new RawIpPrivilegeChecker().IsElevated;
        }

        [Fact]
        public void Create_WhenNotPermitted_ThrowsWithPrivilegeGuidance()
        {
            var factory = new RawIpTransportFactory(new FakePrivilegeChecker(isElevated: false));
            if (factory.IsAvailable) return; // running elevated (e.g. CI as root): the denied-open path cannot be exercised

            var ex = Assert.Throws<RawIpNotPermittedException>(
                () => factory.Create(IPAddress.Loopback, RawIpProtocols.Esp));
            Assert.Contains("CAP_NET_RAW", ex.Message);
        }

        /// <summary>
        /// Regression for the P0.8c live finding: the managed <see cref="System.Net.Sockets.Socket"/> ctor
        /// <c>new Socket(InterNetwork, Raw, (ProtocolType)50)</c> fails on Linux with
        /// <see cref="System.Net.Sockets.SocketError.ProtocolNotSupported"/> (errno EPROTONOSUPPORT) <b>even as root</b>,
        /// although the kernel supports the call — so native ESP never opened a carrier. The factory now goes through
        /// <c>NativeRawSocket</c> (libc <c>socket()</c> on Unix), so when elevated the ESP raw socket must open. Lives in
        /// the integration set (needs root / CAP_NET_RAW); skipped otherwise.
        /// </summary>
        [Fact]
        [Trait("Category", "Integration")]
        public async Task Create_OpensEspRawSocket_WhenElevated()
        {
            if (!new RawIpPrivilegeChecker().IsElevated) return; // needs root/admin; cannot exercise the open path otherwise

            var factory = new RawIpTransportFactory();
            Assert.True(factory.IsAvailable, "elevated ESP raw probe must succeed via the libc path (not ProtocolNotSupported)");

            var transport = factory.Create(IPAddress.Loopback, RawIpProtocols.Esp);
            Assert.NotNull(transport);
            await transport.DisposeAsync();
        }

        sealed class FakePrivilegeChecker : IPrivilegeChecker
        {
            public FakePrivilegeChecker(bool isElevated) => IsElevated = isElevated;
            public bool IsElevated { get; }
        }
    }
}
