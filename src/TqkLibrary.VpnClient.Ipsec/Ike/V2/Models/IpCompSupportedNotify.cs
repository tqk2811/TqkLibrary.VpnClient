using System.Buffers.Binary;
using System.Collections.Generic;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads;
using TqkLibrary.VpnClient.Ipsec.IpComp.Enums;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Models
{
    /// <summary>
    /// The body of an IKEv2 IPCOMP_SUPPORTED notification (RFC 7296 §3.10.1): a 2-octet big-endian IPComp CPI
    /// followed by a 1-octet IPComp transform ID (2 = DEFLATE, RFC 2394). Advertised beside the CHILD_SA in IKE_AUTH
    /// to negotiate RFC 3173 payload compression; the CPI a side advertises is the CPI its peer must stamp in the
    /// IPComp header of packets it sends back to that side.
    /// </summary>
    public readonly struct IpCompSupportedNotify
    {
        /// <summary>Wire length of the notification data: CPI (2) + transform ID (1).</summary>
        public const int DataSize = 3;

        /// <summary>The Compression Parameter Index the notify's sender will recognise on inbound IPComp packets.</summary>
        public ushort Cpi { get; }

        /// <summary>The IPComp transform (only <see cref="IpCompTransform.Deflate"/> is implemented here, RFC 2394).</summary>
        public IpCompTransform Transform { get; }

        /// <summary>Creates a notification body with an explicit <paramref name="cpi"/> and <paramref name="transform"/>.</summary>
        public IpCompSupportedNotify(ushort cpi, IpCompTransform transform)
        {
            Cpi = cpi;
            Transform = transform;
        }

        /// <summary>An IPCOMP_SUPPORTED body advertising <paramref name="cpi"/> for the DEFLATE transform (RFC 2394).</summary>
        public static IpCompSupportedNotify Deflate(ushort cpi) => new(cpi, IpCompTransform.Deflate);

        /// <summary>Serialises the 3-byte notification data: CPI big-endian, then the 1-octet transform ID.</summary>
        public byte[] ToNotifyData()
        {
            byte[] data = new byte[DataSize];
            BinaryPrimitives.WriteUInt16BigEndian(data, Cpi);
            data[2] = (byte)Transform;
            return data;
        }

        /// <summary>Wraps this as an IKE Notify payload of type IPCOMP_SUPPORTED (Protocol ID 0, SPI Size 0).</summary>
        public NotifyPayload ToNotifyPayload()
            => NotifyPayload.Create(IkeNotifyMessageType.IpcompSupported, ToNotifyData());

        /// <summary>
        /// Parses an IPCOMP_SUPPORTED notification body; returns <c>false</c> (with <paramref name="notify"/> defaulted)
        /// when it is shorter than <see cref="DataSize"/>.
        /// </summary>
        public static bool TryParse(ReadOnlySpan<byte> data, out IpCompSupportedNotify notify)
        {
            if (data.Length < DataSize)
            {
                notify = default;
                return false;
            }
            ushort cpi = BinaryPrimitives.ReadUInt16BigEndian(data);
            notify = new IpCompSupportedNotify(cpi, (IpCompTransform)data[2]);
            return true;
        }

        /// <summary>
        /// Selects the outbound IPComp CPI from a peer's notifies: the CPI of the first IPCOMP_SUPPORTED
        /// (RFC 7296 §3.10.1) advertising the DEFLATE transform (RFC 2394), or <c>null</c> when the peer sent none (or
        /// only non-DEFLATE transforms) — in which case IPComp is not active and traffic runs over plain ESP.
        /// </summary>
        public static ushort? FindDeflateCpi(IEnumerable<NotifyPayload> notifies)
        {
            foreach (NotifyPayload notify in notifies)
            {
                if (notify.KnownType != IkeNotifyMessageType.IpcompSupported) continue;
                if (TryParse(notify.Data, out IpCompSupportedNotify parsed) && parsed.Transform == IpCompTransform.Deflate)
                    return parsed.Cpi;
            }
            return null;
        }
    }
}
