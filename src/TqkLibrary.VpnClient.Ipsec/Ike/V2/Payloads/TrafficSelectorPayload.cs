using System.Net;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads
{
    /// <summary>One traffic selector substructure (RFC 7296 §3.13.1), IPv4 address range form (TS Type 7).</summary>
    public sealed class TrafficSelector
    {
        /// <summary>TS Type — 7 for TS_IPV4_ADDR_RANGE.</summary>
        public const byte TypeIpv4AddrRange = 7;

        /// <summary>IP protocol ID (0 = any).</summary>
        public byte Protocol { get; set; }

        /// <summary>Inclusive start port.</summary>
        public ushort StartPort { get; set; }

        /// <summary>Inclusive end port.</summary>
        public ushort EndPort { get; set; } = 0xFFFF;

        /// <summary>Inclusive start address.</summary>
        public IPAddress StartAddress { get; set; } = IPAddress.Any;

        /// <summary>Inclusive end address.</summary>
        public IPAddress EndAddress { get; set; } = IPAddress.Broadcast;

        /// <summary>A selector matching every IPv4 address, port and protocol.</summary>
        public static TrafficSelector AnyIpv4() => new()
        {
            Protocol = 0,
            StartPort = 0,
            EndPort = 0xFFFF,
            StartAddress = IPAddress.Any,
            EndAddress = IPAddress.Broadcast,
        };

        internal void Write(List<byte> output)
        {
            byte[] start = StartAddress.GetAddressBytes();
            byte[] end = EndAddress.GetAddressBytes();
            int length = 8 + start.Length + end.Length;
            output.Add(TypeIpv4AddrRange);
            output.Add(Protocol);
            IkeBuffer.WriteUInt16(output, (ushort)length);
            IkeBuffer.WriteUInt16(output, StartPort);
            IkeBuffer.WriteUInt16(output, EndPort);
            output.AddRange(start);
            output.AddRange(end);
        }

        internal static TrafficSelector Parse(ReadOnlySpan<byte> ts)
        {
            int addressLength = (IkeBuffer.ReadUInt16(ts, 2) - 8) / 2;
            return new TrafficSelector
            {
                Protocol = ts[1],
                StartPort = IkeBuffer.ReadUInt16(ts, 4),
                EndPort = IkeBuffer.ReadUInt16(ts, 6),
                StartAddress = new IPAddress(ts.Slice(8, addressLength).ToArray()),
                EndAddress = new IPAddress(ts.Slice(8 + addressLength, addressLength).ToArray()),
            };
        }
    }

    /// <summary>A TSi or TSr payload: a count-prefixed list of traffic selectors (RFC 7296 §3.13).</summary>
    public sealed class TrafficSelectorPayload : IkePayload
    {
        /// <summary>True for TSi (initiator), false for TSr (responder).</summary>
        public bool IsInitiator { get; set; } = true;

        /// <inheritdoc/>
        public override IkePayloadType Type
            => IsInitiator ? IkePayloadType.TrafficSelectorInitiator : IkePayloadType.TrafficSelectorResponder;

        /// <summary>The traffic selectors.</summary>
        public List<TrafficSelector> Selectors { get; } = new();

        /// <summary>Builds a TSi/TSr payload offering a single "match all IPv4" selector.</summary>
        public static TrafficSelectorPayload AnyIpv4(bool isInitiator)
        {
            var payload = new TrafficSelectorPayload { IsInitiator = isInitiator };
            payload.Selectors.Add(TrafficSelector.AnyIpv4());
            return payload;
        }

        /// <summary>
        /// Builds a TSi/TSr payload offering several traffic selectors (RFC 7296 §3.13 allows more than one — e.g. a
        /// split-tunnel that protects several subnets). Falls back to a single "match all IPv4" selector when the list
        /// is empty so callers can pass through a null/empty configuration unchanged.
        /// </summary>
        public static TrafficSelectorPayload Multiple(bool isInitiator, IEnumerable<TrafficSelector>? selectors)
        {
            var payload = new TrafficSelectorPayload { IsInitiator = isInitiator };
            if (selectors is not null)
                foreach (TrafficSelector selector in selectors)
                    payload.Selectors.Add(selector);
            if (payload.Selectors.Count == 0)
                payload.Selectors.Add(TrafficSelector.AnyIpv4());
            return payload;
        }

        /// <summary>A traffic selector for the IPv4 subnet <paramref name="network"/>/<paramref name="prefixLength"/> (all protocols/ports).</summary>
        public static TrafficSelector Subnet(IPAddress network, int prefixLength)
        {
            if (network.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new ArgumentException("Only IPv4 subnets are supported (TS_IPV4_ADDR_RANGE).", nameof(network));
            if (prefixLength < 0 || prefixLength > 32)
                throw new ArgumentOutOfRangeException(nameof(prefixLength));

            byte[] networkBytes = network.GetAddressBytes();
            uint mask = prefixLength == 0 ? 0u : 0xFFFFFFFFu << (32 - prefixLength);
            uint baseAddress =
                ((uint)networkBytes[0] << 24) | ((uint)networkBytes[1] << 16) | ((uint)networkBytes[2] << 8) | networkBytes[3];
            uint start = baseAddress & mask;
            uint end = start | ~mask;

            return new TrafficSelector
            {
                Protocol = 0,
                StartPort = 0,
                EndPort = 0xFFFF,
                StartAddress = FromUInt32(start),
                EndAddress = FromUInt32(end),
            };
        }

        static IPAddress FromUInt32(uint value)
            => new(new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value });

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output)
        {
            output.Add((byte)Selectors.Count);
            output.Add(0); output.Add(0); output.Add(0); // reserved
            foreach (TrafficSelector selector in Selectors)
                selector.Write(output);
        }

        internal static TrafficSelectorPayload Parse(ReadOnlySpan<byte> body, bool isInitiator)
        {
            var payload = new TrafficSelectorPayload { IsInitiator = isInitiator };
            int count = body[0];
            int offset = 4;
            for (int i = 0; i < count && offset + 8 <= body.Length; i++)
            {
                int length = IkeBuffer.ReadUInt16(body, offset + 2);
                if (length < 8 || offset + length > body.Length) break;
                payload.Selectors.Add(TrafficSelector.Parse(body.Slice(offset, length)));
                offset += length;
            }
            return payload;
        }
    }
}
