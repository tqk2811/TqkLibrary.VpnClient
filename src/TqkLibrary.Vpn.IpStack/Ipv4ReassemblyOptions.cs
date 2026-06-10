namespace TqkLibrary.Vpn.IpStack
{
    /// <summary>
    /// Tunables for <see cref="Ipv4Reassembler"/>. Defaults follow RFC 791 §3.2 (a 15-second reassembly timeout)
    /// with conservative DoS bounds. No <c>record</c>/<c>init</c> so the type compiles on <c>netstandard2.0</c>.
    /// </summary>
    public sealed class Ipv4ReassemblyOptions
    {
        /// <summary>Maximum time to hold an incomplete datagram before discarding its fragments (RFC 791 §3.2).</summary>
        public TimeSpan Timeout { get; }

        /// <summary>Maximum number of in-progress (incomplete) datagrams buffered at once; the oldest is evicted when exceeded.</summary>
        public int MaxConcurrent { get; }

        /// <summary>Maximum reassembled datagram size in bytes (header + payload); fragments that would exceed it are dropped.</summary>
        public int MaxDatagramSize { get; }

        /// <summary>Creates reassembly options; any unspecified value uses its RFC/safe default.</summary>
        public Ipv4ReassemblyOptions(TimeSpan? timeout = null, int maxConcurrent = 64, int maxDatagramSize = 65535)
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(15);
            MaxConcurrent = maxConcurrent > 0 ? maxConcurrent : 64;
            MaxDatagramSize = (maxDatagramSize > 0 && maxDatagramSize <= 65535) ? maxDatagramSize : 65535;
        }

        /// <summary>Shared default options.</summary>
        public static readonly Ipv4ReassemblyOptions Default = new Ipv4ReassemblyOptions();
    }
}
