using System.Runtime.InteropServices;
#if NET5_0_OR_GREATER
using System.Security.Principal;
#endif
using TqkLibrary.VpnClient.Transport.RawIp.Interfaces;

namespace TqkLibrary.VpnClient.Transport.RawIp
{
    /// <summary>
    /// Default <see cref="IPrivilegeChecker"/>: on Windows tests the Administrator role, on Linux/macOS tests euid == 0
    /// via a single libc P/Invoke (no Mono.Posix). This is a heuristic for error messages only — a process holding the
    /// Linux CAP_NET_RAW capability is not euid 0 yet can open a raw socket, so a <c>false</c> here is not "cannot open".
    /// </summary>
    public sealed class RawIpPrivilegeChecker : IPrivilegeChecker
    {
        /// <inheritdoc/>
        public bool IsElevated
        {
            get
            {
                try
                {
#if NET5_0_OR_GREATER
                    if (OperatingSystem.IsWindows())
                        return IsWindowsAdministrator();
                    if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
                        return geteuid() == 0;
#else
                    // WindowsIdentity is outside the netstandard2.0 surface (it needs an extra package); fall back to the
                    // socket probe for Windows under this TFM. Unix euid is still a plain libc call.
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                        return geteuid() == 0;
#endif
                }
                catch { }
                return false;
            }
        }

#if NET5_0_OR_GREATER
        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        static bool IsWindowsAdministrator()
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
#endif

        [DllImport("libc", EntryPoint = "geteuid")]
        static extern uint geteuid();
    }
}
