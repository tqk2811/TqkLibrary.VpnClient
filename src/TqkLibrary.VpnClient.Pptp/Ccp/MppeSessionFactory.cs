using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Mppe;
using TqkLibrary.VpnClient.Crypto.Mppe.Enums;

namespace TqkLibrary.VpnClient.Pptp.Ccp
{
    /// <summary>
    /// Builds the pair of <see cref="MppeSession"/> directions for the PPTP data plane from the MS-CHAPv2
    /// authentication result and the CCP-negotiated MPPE parameters — the glue that joins the existing crypto
    /// (F.5b: <see cref="MsChapV2"/> MPPE start keys + <see cref="MppeSession"/>) to the CCP negotiation
    /// (<see cref="CcpNegotiator"/>).
    /// <para>
    /// The keys come from the user password and the 24-byte NT-Response computed during MS-CHAPv2:
    /// <c>MasterKey = DeriveMppeMasterKey(password, ntResponse)</c>, then the asymmetric Send/Receive start keys
    /// (RFC 3079 §3.3). A PPTP client encrypts with its Send key and decrypts with its Receive key.
    /// </para>
    /// <b>MS-CHAPv2 + MPPE/RC4 is cryptographically broken</b> — provided only for interoperability with legacy
    /// PPTP servers.
    /// </summary>
    public static class MppeSessionFactory
    {
        /// <summary>
        /// Derives the client's send + receive <see cref="MppeSession"/> from the user's
        /// <paramref name="password"/>, the MS-CHAPv2 <paramref name="ntResponse"/> (24 bytes), and the negotiated
        /// CCP option (<paramref name="negotiated"/>).
        /// </summary>
        /// <returns>A tuple of <c>send</c> (encrypt our outbound PPP payloads) and <c>receive</c> (decrypt inbound).</returns>
        public static (MppeSession send, MppeSession receive) CreateClientSessions(
            string password, byte[] ntResponse, MppeConfigOption negotiated)
        {
            if (negotiated is null) throw new ArgumentNullException(nameof(negotiated));
            if (!negotiated.HasEncryption)
                throw new InvalidOperationException("Negotiated CCP option carries no MPPE encryption strength.");

            MppeKeyStrength strength = negotiated.Strength;
            bool stateless = negotiated.Stateless;

            byte[] masterKey = MsChapV2.DeriveMppeMasterKey(password, ntResponse);
            byte[] sendStart = MsChapV2.DeriveMppeSendStartKey(masterKey, isServer: false);
            byte[] receiveStart = MsChapV2.DeriveMppeReceiveStartKey(masterKey, isServer: false);

            var send = new MppeSession(sendStart, strength, stateless);
            var receive = new MppeSession(receiveStart, strength, stateless);
            return (send, receive);
        }

        /// <summary>
        /// Derives the <b>server's</b> send + receive <see cref="MppeSession"/> — the mirror of
        /// <see cref="CreateClientSessions"/> with RFC 3079 §3.3 <c>isServer:true</c>, so the server's send key equals
        /// the client's receive key and vice versa (the two ends interoperate). Symmetric helper used by the PPTP
        /// data plane's peer/responder role and by offline tests; the same MS-CHAPv2 <paramref name="ntResponse"/>
        /// (24 bytes) and <paramref name="password"/> the client used.
        /// </summary>
        /// <returns>A tuple of <c>send</c> (encrypt the server's outbound payloads) and <c>receive</c> (decrypt the client's).</returns>
        public static (MppeSession send, MppeSession receive) CreateServerSessions(
            string password, byte[] ntResponse, MppeConfigOption negotiated)
        {
            if (negotiated is null) throw new ArgumentNullException(nameof(negotiated));
            if (!negotiated.HasEncryption)
                throw new InvalidOperationException("Negotiated CCP option carries no MPPE encryption strength.");

            MppeKeyStrength strength = negotiated.Strength;
            bool stateless = negotiated.Stateless;

            byte[] masterKey = MsChapV2.DeriveMppeMasterKey(password, ntResponse);
            byte[] sendStart = MsChapV2.DeriveMppeSendStartKey(masterKey, isServer: true);
            byte[] receiveStart = MsChapV2.DeriveMppeReceiveStartKey(masterKey, isServer: true);

            var send = new MppeSession(sendStart, strength, stateless);
            var receive = new MppeSession(receiveStart, strength, stateless);
            return (send, receive);
        }
    }
}
