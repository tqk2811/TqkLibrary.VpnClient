namespace TqkLibrary.VpnClient.Transport.RawIp
{
    /// <summary>Well-known IANA IP protocol numbers carried natively (no UDP/TCP wrapper) over a raw-IP transport.</summary>
    public static class RawIpProtocols
    {
        /// <summary>Encapsulating Security Payload (IPsec ESP) — IANA IP protocol 50.</summary>
        public const int Esp = 50;

        /// <summary>Generic Routing Encapsulation (GRE, used by PPTP) — IANA IP protocol 47.</summary>
        public const int Gre = 47;
    }
}
