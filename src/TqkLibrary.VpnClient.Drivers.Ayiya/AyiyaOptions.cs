using System;
using System.Net;
using System.Text;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Ayiya.Enums;

namespace TqkLibrary.VpnClient.Drivers.Ayiya
{
    /// <summary>
    /// Static configuration for a <see cref="AyiyaConnection"/> — the parts of an aiccu tunnel a client needs to bring an
    /// AYIYA (Anything In Anything) IPv6-over-UDP tunnel up in <b>static mode</b>: the TIC control channel is skipped, so
    /// the endpoint, identity and shared secret are all fixed up front by the caller (the remote tunnel-broker host is the
    /// <c>VpnEndpoint.Host</c> passed to the driver). AYIYA has no in-band negotiation.
    /// <para><b>AYIYA does not encrypt the payload</b> — it signs integrity with the shared-secret hash and guards replay
    /// with the epoch time. Use only on a trusted path or wrap the tunnel in an outer secure layer.</para>
    /// </summary>
    public sealed record AyiyaOptions
    {
        /// <summary>The UDP destination port. Default 5072 (the port aiccu / SixXS AYIYA deployments use).</summary>
        public int Port { get; init; } = 5072;

        /// <summary>
        /// The AYIYA identity bytes (the value carried in the identity field, e.g. the client's 16-byte IPv6 tunnel
        /// endpoint for <see cref="AyiyaIdType.Ipv6"/>, or a login for <see cref="AyiyaIdType.String"/>). Its length must be
        /// a power of two (idlen = log2(length); 16 → idlen 4). Required.
        /// </summary>
        public required byte[] Identity { get; init; }

        /// <summary>What the <see cref="Identity"/> field carries. Default <see cref="AyiyaIdType.Ipv6"/>.</summary>
        public AyiyaIdType IdType { get; init; } = AyiyaIdType.Ipv6;

        /// <summary>The shared secret (tunnel password). Hashed with <see cref="HashMethod"/> to key the signature. Required.</summary>
        public required string Password { get; init; }

        /// <summary>The hash method for the signature. Default <see cref="AyiyaHashMethod.Sha1"/> (aiccu / SixXS).</summary>
        public AyiyaHashMethod HashMethod { get; init; } = AyiyaHashMethod.Sha1;

        /// <summary>The authentication method. Only <see cref="AyiyaAuthMethod.SharedSecret"/> is implemented. Default shared-secret.</summary>
        public AyiyaAuthMethod AuthMethod { get; init; } = AyiyaAuthMethod.SharedSecret;

        /// <summary>Inner-packet MTU advertised to the IP stack. Default 1280 (the IPv6 minimum link MTU — a safe tunnel-broker default).</summary>
        public int Mtu { get; init; } = 1280;

        /// <summary>Maximum accepted |now − packet-epoch| in seconds on receive (the replay/clock-skew guard). Default 120.</summary>
        public int ClockSkewToleranceSeconds { get; init; } = 120;

        /// <summary>The static IPv6 address the tunnel broker assigned this client endpoint (surfaced on the TunnelConfig); null → out of band.</summary>
        public IPAddress? AssignedAddressV6 { get; init; }

        /// <summary>Prefix length of <see cref="AssignedAddressV6"/> (e.g. 64 for a routed /64). Default 64.</summary>
        public int PrefixLengthV6 { get; init; } = 64;

        /// <summary>The shared secret encoded as UTF-8 bytes (what is hashed to key the signature).</summary>
        public byte[] PasswordBytes => Encoding.UTF8.GetBytes(Password ?? string.Empty);

        /// <summary>
        /// Validates the configuration and returns the derived <c>H(password)</c> (the digest placed into the signature
        /// field before signing). Throws when the identity length is not a power of two, the password is empty, or the
        /// hash/auth method is unsupported.
        /// </summary>
        public byte[] ValidateAndComputeSecretHash()
        {
            if (Identity is null || Identity.Length == 0)
                throw new ArgumentException("AyiyaOptions.Identity is required and must be non-empty.", nameof(Identity));
            AyiyaPacket.IdLenFor(Identity.Length); // throws if not a power of two
            if (string.IsNullOrEmpty(Password))
                throw new ArgumentException("AyiyaOptions.Password (shared secret) is required.", nameof(Password));
            if (AuthMethod != AyiyaAuthMethod.SharedSecret)
                throw new NotSupportedException($"AYIYA auth method {AuthMethod} is not supported (only shared-secret).");
            if (HashMethod != AyiyaHashMethod.Sha1 && HashMethod != AyiyaHashMethod.Md5)
                throw new NotSupportedException($"AYIYA hash method {HashMethod} is not supported (only MD5 or SHA-1).");
            return AyiyaPacket.HashPassword(HashMethod, PasswordBytes);
        }

        /// <summary>
        /// Projects this configuration onto a <see cref="TunnelConfig"/> — always the MTU, and the assigned IPv6 address /
        /// prefix when <see cref="AssignedAddressV6"/> is set (otherwise the address is out of band).
        /// </summary>
        public TunnelConfig ToTunnelConfig()
        {
            var config = new TunnelConfig { Mtu = Mtu };
            if (AssignedAddressV6 is not null)
            {
                config.AssignedAddressV6 = AssignedAddressV6;
                config.PrefixLengthV6 = PrefixLengthV6;
            }
            return config;
        }
    }
}
