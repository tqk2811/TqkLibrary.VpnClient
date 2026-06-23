using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace TqkLibrary.VpnClient.Transport.RawIp
{
    /// <summary>
    /// Opens a raw IP socket for an arbitrary IP protocol (ESP-50, GRE-47, …). The managed
    /// <see cref="Socket"/> constructor cannot do this on Unix: the .NET runtime's protocol-conversion layer
    /// rejects unknown protocol numbers, so <c>new Socket(InterNetwork, Raw, (ProtocolType)50)</c> fails with
    /// <see cref="SocketError.ProtocolNotSupported"/> (errno EPROTONOSUPPORT) <b>even as root</b>, although the
    /// kernel itself supports the call (verified: libc <c>socket(AF_INET, SOCK_RAW, 50)</c> succeeds). So on Unix we
    /// open the descriptor through libc and adopt it with a <see cref="SafeSocketHandle"/>, which bypasses that layer;
    /// on Windows the managed constructor works (best-effort) and is used directly.
    /// </summary>
    static class NativeRawSocket
    {
        /// <summary>Creates a raw socket of <paramref name="ipProtocol"/> in the given address family.</summary>
        public static Socket Create(AddressFamily family, int ipProtocol)
        {
#if NETSTANDARD2_0
            // netstandard2.0 has no public SafeSocketHandle(IntPtr, bool) ctor to adopt a libc fd, so it falls back to
            // the managed path (correct on Windows; on Unix the runtime may reject unknown raw protocols). The shipping
            // runtime for native-ESP is net8.0, which takes the libc path below.
            return new Socket(family, SocketType.Raw, (ProtocolType)ipProtocol);
#else
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return new Socket(family, SocketType.Raw, (ProtocolType)ipProtocol);

            int fd = socket(DomainFor(family), SOCK_RAW, ipProtocol);
            if (fd < 0)
                throw new SocketException(Marshal.GetLastWin32Error());
            return new Socket(new SafeSocketHandle((System.IntPtr)fd, ownsHandle: true));
#endif
        }

#if !NETSTANDARD2_0
        const int SOCK_RAW = 3; // Linux/macOS

        // AF_INET is 2 everywhere; AF_INET6 is 10 on Linux but 30 on macOS/BSD.
        static int DomainFor(AddressFamily family)
        {
            if (family == AddressFamily.InterNetworkV6)
                return RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? 30 : 10;
            return 2;
        }

        [DllImport("libc", SetLastError = true)]
        static extern int socket(int domain, int type, int protocol);
#endif
    }
}
