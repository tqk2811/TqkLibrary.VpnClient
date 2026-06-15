using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// Builds the OpenVPN peer-info block (the <c>IV_*</c> lines) the client sends inside its key-method-2 message.
    /// The server reads <c>IV_PROTO</c> (capabilities) and <c>IV_CIPHERS</c> (the NCP cipher list) to choose the data
    /// cipher, then echoes its pick in PUSH_REPLY (<c>cipher …</c>). Beyond that minimal set, an OpenVPN 2.6 client run
    /// with <c>--push-peer-info</c> also advertises <c>IV_MTU</c> (the tun MTU it can carry) plus informational
    /// <c>IV_PLAT_VER</c>/<c>IV_SSL_VER</c>/<c>IV_GUI_VER</c> and arbitrary user variables (<c>UV_*</c>) — all modelled by
    /// <see cref="OpenVpnPeerInfoOptions"/>. See <see cref="OpenVpnDataCipher"/> for the advertised cipher list and
    /// <see cref="OpenVpnKeyMethod2.BuildClientMessage"/> for where the block is carried.
    /// </summary>
    public static class OpenVpnPeerInfo
    {
        /// <summary><c>IV_PROTO</c> bit: the peer understands P_DATA_V2 (peer-id data packets).</summary>
        public const int IvProtoDataV2 = 1 << 1;

        /// <summary><c>IV_PROTO</c> bit: the peer will send PUSH_REQUEST proactively after connecting.</summary>
        public const int IvProtoRequestPush = 1 << 2;

        /// <summary><c>IV_PROTO</c> bit: the peer can export TLS keying material for the data channel (<c>tls-ekm</c>; roadmap F.5 — not set yet).</summary>
        public const int IvProtoTlsKeyExport = 1 << 3;

        /// <summary><c>IV_PROTO</c> bit: the peer signals session end over the control channel (explicit-exit-notify; roadmap — not set yet).</summary>
        public const int IvProtoCcExitNotify = 1 << 7;

        /// <summary>
        /// Builds the peer-info string (newline-separated <c>IV_*</c> lines) from <paramref name="options"/>
        /// (null = defaults: auto-detected platform, the advertised cipher list, DATA_V2 | REQUEST_PUSH).
        /// </summary>
        public static string Build(OpenVpnPeerInfoOptions? options = null)
        {
            options ??= new OpenVpnPeerInfoOptions();
            string ciphers = string.IsNullOrEmpty(options.Ciphers) ? OpenVpnDataCipher.AdvertisedList : options.Ciphers!;
            string platform = string.IsNullOrEmpty(options.Platform) ? DetectPlatform() : options.Platform!;

            var sb = new StringBuilder();
            sb.Append("IV_VER=").Append(options.Version).Append('\n');
            sb.Append("IV_PLAT=").Append(platform).Append('\n');
            sb.Append("IV_PROTO=").Append(options.IvProto).Append('\n');
            sb.Append("IV_NCP=2\n");
            sb.Append("IV_CIPHERS=").Append(ciphers).Append('\n');
            if (options.Mtu is int mtu) sb.Append("IV_MTU=").Append(mtu).Append('\n');
            AppendIfPresent(sb, "IV_PLAT_VER", options.PlatformVersion);
            AppendIfPresent(sb, "IV_SSL_VER", options.SslVersion);
            AppendIfPresent(sb, "IV_GUI_VER", options.GuiVersion);
            if (options.Extra != null)
                foreach (KeyValuePair<string, string> kv in options.Extra)
                    sb.Append(kv.Key).Append('=').Append(kv.Value).Append('\n');
            return sb.ToString();
        }

        static void AppendIfPresent(StringBuilder sb, string key, string? value)
        {
            if (!string.IsNullOrEmpty(value))
                sb.Append(key).Append('=').Append(value).Append('\n');
        }

        /// <summary>The OpenVPN platform tag for the running OS (<c>linux</c>/<c>win</c>/<c>mac</c>; <c>dotnet</c> otherwise).</summary>
        public static string DetectPlatform()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return "win";
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) return "mac";
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return "linux";
            return "dotnet";
        }

        /// <summary>A human-readable OS version string for <c>IV_PLAT_VER</c> (e.g. the running OS description).</summary>
        public static string DetectPlatformVersion() => RuntimeInformation.OSDescription;

        /// <summary>The TLS stack identity for <c>IV_SSL_VER</c> — here the managed runtime (.NET's TLS), e.g. <c>.NET 8.0.x</c>.</summary>
        public static string DetectSslVersion() => RuntimeInformation.FrameworkDescription;
    }

    /// <summary>
    /// The fields a client advertises in its peer-info block (see <see cref="OpenVpnPeerInfo.Build"/>). The minimal set
    /// (<c>IV_VER</c>/<c>IV_PLAT</c>/<c>IV_PROTO</c>/<c>IV_NCP</c>/<c>IV_CIPHERS</c>) is always emitted; <see cref="Mtu"/>
    /// and the optional informational lines mirror what OpenVPN 2.6 sends under <c>--push-peer-info</c>. Set any optional
    /// string to null (or empty) to omit its line; <see cref="Extra"/> carries arbitrary extra entries such as user
    /// variables (<c>UV_*</c>).
    /// </summary>
    public sealed record OpenVpnPeerInfoOptions
    {
        /// <summary>The colon-separated NCP cipher list (null/empty = <see cref="OpenVpnDataCipher.AdvertisedList"/>).</summary>
        public string? Ciphers { get; init; }

        /// <summary>The <c>IV_PROTO</c> capability bitmask (default DATA_V2 | REQUEST_PUSH).</summary>
        public int IvProto { get; init; } = OpenVpnPeerInfo.IvProtoDataV2 | OpenVpnPeerInfo.IvProtoRequestPush;

        /// <summary>The <c>IV_VER</c> OpenVPN version string the client claims.</summary>
        public string Version { get; init; } = "2.6.0";

        /// <summary>The <c>IV_PLAT</c> platform tag (null/empty = auto-detect via <see cref="OpenVpnPeerInfo.DetectPlatform"/>).</summary>
        public string? Platform { get; init; }

        /// <summary>The <c>IV_MTU</c> tunnel MTU the client can carry (null = omit). The connection fills its tun MTU when unset.</summary>
        public int? Mtu { get; init; }

        /// <summary>The <c>IV_PLAT_VER</c> OS version line (default: auto-detected; null = omit).</summary>
        public string? PlatformVersion { get; init; } = OpenVpnPeerInfo.DetectPlatformVersion();

        /// <summary>The <c>IV_SSL_VER</c> TLS-stack line (default: auto-detected; null = omit).</summary>
        public string? SslVersion { get; init; } = OpenVpnPeerInfo.DetectSslVersion();

        /// <summary>The <c>IV_GUI_VER</c> GUI/app version line (null = omit).</summary>
        public string? GuiVersion { get; init; }

        /// <summary>Arbitrary extra peer-info entries appended verbatim as <c>key=value</c> lines (e.g. user variables <c>UV_*</c>).</summary>
        public IReadOnlyList<KeyValuePair<string, string>>? Extra { get; init; }
    }
}
