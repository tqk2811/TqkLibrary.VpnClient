using System.Security.Cryptography;
using System.Text;
using TqkLibrary.Vpn.Ppp.Enums;
using TqkLibrary.Vpn.Ppp.Interfaces;

namespace TqkLibrary.Vpn.Ppp.Auth
{
    /// <summary>
    /// Client-side MS-CHAPv2 authenticator over PPP CHAP (RFC 1994 + RFC 2759). Answers the server's
    /// Challenge with a 49-byte MS-CHAPv2 Response and reports Success/Failure.
    /// </summary>
    public sealed class MsChapV2Authenticator : IPppAuthenticator
    {
        const byte ChapChallenge = 1;
        const byte ChapResponse = 2;
        const byte ChapSuccess = 3;
        const byte ChapFailure = 4;

        readonly string _userName;
        readonly string _password;

        /// <summary>Creates an authenticator for the given credentials.</summary>
        public MsChapV2Authenticator(string userName, string password)
        {
            _userName = userName;
            _password = password;
        }

        /// <inheritdoc/>
        public ushort Protocol => 0xC223; // CHAP

        /// <summary>The 16-byte authenticator challenge from the server (available after the Challenge).</summary>
        public byte[]? AuthenticatorChallenge { get; private set; }

        /// <summary>The 16-byte peer challenge we generated.</summary>
        public byte[]? PeerChallenge { get; private set; }

        /// <summary>The 24-byte NT-Response we sent (used later for SSTP HLAK derivation).</summary>
        public byte[]? NtResponse { get; private set; }

        /// <summary>Derives the 32-byte HLAK for the SSTP crypto binding (valid after a successful auth).</summary>
        public byte[] DeriveHlak()
        {
            if (NtResponse == null) throw new InvalidOperationException("Authentication has not produced an NT-Response yet.");
            return MsChapV2.DeriveHlak(_password, NtResponse);
        }

        /// <inheritdoc/>
        public PppAuthStatus Handle(ReadOnlySpan<byte> packet, out byte[]? response)
        {
            response = null;
            if (packet.Length < 4) return PppAuthStatus.Pending;

            byte code = packet[0];
            byte id = packet[1];

            switch (code)
            {
                case ChapChallenge:
                    response = BuildResponse(id, packet);
                    return PppAuthStatus.Pending;
                case ChapSuccess:
                    return PppAuthStatus.Success;
                case ChapFailure:
                    return PppAuthStatus.Failure;
                default:
                    return PppAuthStatus.Pending;
            }
        }

        byte[] BuildResponse(byte id, ReadOnlySpan<byte> challengePacket)
        {
            int valueSize = challengePacket[4];
            byte[] authChallenge = challengePacket.Slice(5, valueSize).ToArray();

            byte[] peerChallenge = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(peerChallenge);

            byte[] ntResponse = MsChapV2.GenerateNTResponse(authChallenge, peerChallenge, _userName, _password);

            AuthenticatorChallenge = authChallenge;
            PeerChallenge = peerChallenge;
            NtResponse = ntResponse;

            // MS-CHAPv2 response value (49 bytes): PeerChallenge(16) + Reserved(8) + NT-Response(24) + Flags(1).
            byte[] value = new byte[49];
            Buffer.BlockCopy(peerChallenge, 0, value, 0, 16);
            Buffer.BlockCopy(ntResponse, 0, value, 24, 24);
            value[48] = 0x00; // Flags

            byte[] nameBytes = Encoding.ASCII.GetBytes(_userName);
            int length = 4 + 1 + value.Length + nameBytes.Length; // header + value-size + value + name

            byte[] chap = new byte[length];
            chap[0] = ChapResponse;
            chap[1] = id;
            chap[2] = (byte)(length >> 8);
            chap[3] = (byte)(length & 0xff);
            chap[4] = (byte)value.Length;
            Buffer.BlockCopy(value, 0, chap, 5, value.Length);
            Buffer.BlockCopy(nameBytes, 0, chap, 5 + value.Length, nameBytes.Length);
            return chap;
        }
    }
}
