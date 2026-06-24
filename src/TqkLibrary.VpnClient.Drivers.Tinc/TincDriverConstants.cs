namespace TqkLibrary.VpnClient.Drivers.Tinc
{
    /// <summary>Shared constants for the tinc driver's meta protocol, data plane and timers.</summary>
    public static class TincDriverConstants
    {
        /// <summary>The default tinc meta/data port (TCP for the meta-connection, UDP for the data plane).</summary>
        public const int DefaultPort = 655;

        /// <summary>The tinc protocol version this driver speaks (1.1 = major 17, minor 7 — <c>PROT_MAJOR.PROT_MINOR</c>).</summary>
        public const int ProtocolMajor = 17;

        /// <summary>The tinc protocol minor (SPTPS / relay-capable; 7 in 1.1pre18).</summary>
        public const int ProtocolMinor = 7;

        /// <summary>The default tunnel MTU. tinc's <c>MTU</c> is 1518; a conservative 1400 leaves room for the SPTPS/UDP overhead.</summary>
        public const int DefaultMtu = 1400;

        /// <summary>The size in bytes of a tinc node id (the first 6 bytes of <c>SHA512(node_name)</c>).</summary>
        public const int NodeIdLength = 6;

        /// <summary>
        /// The data-plane SPTPS datagram record type for a bare IP packet in <b>router</b> mode: no <c>PKT_MAC</c>
        /// (Ethernet) and no <c>PKT_COMPRESSED</c> bit, i.e. type 0. tinc's <c>send_sptps_packet</c> sends router-mode
        /// packets with this type and the receiver re-derives the Ethernet header from the IP version nibble.
        /// </summary>
        public const byte RouterPacketType = 0;

        /// <summary>The SPTPS record type for a UDP path-MTU / liveness probe (tinc's <c>PKT_PROBE</c>, net.h). A probe
        /// request has <c>data[0] == 0</c>; the reply echoes it with <c>data[0] = 2</c> (type-2, protocol ≥ 17.3).</summary>
        public const byte ProbePacketType = 4;

        /// <summary>The minimum size of a UDP probe packet (tinc's <c>MIN_PROBE_SIZE</c> = 1 + sizeof(uint16)).</summary>
        public const int MinProbeSize = 3;
    }
}
