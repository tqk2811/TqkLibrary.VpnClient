namespace TqkLibrary.VpnClient.Drivers.Fou.Enums
{
    /// <summary>
    /// Which Generic X-over-UDP framing a <see cref="FouConnection"/> puts on the wire. Both modes carry the same inner
    /// IP-protocol payload (IPIP proto 4/41 or GRE proto 47); they differ only in whether an encapsulation header is added.
    /// </summary>
    public enum FouEncapMode
    {
        /// <summary>
        /// Bare Foo-over-UDP (Linux <c>ip fou</c>): there is <b>no encapsulation header</b> — the UDP payload IS the inner
        /// IP-protocol packet, and the inner protocol is inferred from the UDP destination port (fixed by
        /// <see cref="FouOptions.InnerProtocol"/> here). This is the minimal X-over-UDP form.
        /// </summary>
        Fou = 0,

        /// <summary>
        /// GUE variant 0 (draft-ietf-intarea-gue): a 4-byte header <c>Ver(2)|C(1)|Hlen(5) | Proto(8) | Flags(16)</c>
        /// precedes the payload and carries the inner IP protocol number explicitly, so the same UDP port can multiplex
        /// several inner protocols. Extension fields (<c>Hlen*4</c> bytes) are skipped on decode; control messages (C=1)
        /// are dropped.
        /// </summary>
        Gue = 1,
    }
}
