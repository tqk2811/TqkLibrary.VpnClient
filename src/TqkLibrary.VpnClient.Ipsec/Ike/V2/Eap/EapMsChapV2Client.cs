using System;
using System.Security.Cryptography;
using System.Text;
using TqkLibrary.VpnClient.Crypto;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Eap
{
    /// <summary>
    /// Peer-side EAP-MSCHAPv2 state machine (draft-kamath-pppext-eap-mschapv2): consumes the authenticator's EAP
    /// packets and produces the peer's EAP responses, reusing the <see cref="MsChapV2"/> codec (RFC 2759). Handles
    /// the EAP-Identity request, the MS-CHAPv2 Challenge/Response, verifies the server's Success "S=" authenticator
    /// response, and exposes the 64-byte EAP-MSK (RFC 3079) for the IKEv2 AUTH payload (RFC 7296 §2.16).
    /// </summary>
    public sealed class EapMsChapV2Client
    {
        const byte EapTypeIdentity = 1;
        const byte EapTypeMsChapV2 = 26;
        const byte OpChallenge = 1;
        const byte OpResponse = 2;
        const byte OpSuccess = 3;
        const byte OpFailure = 4;

        readonly string _userName;
        readonly string _password;

        byte[]? _authenticatorChallenge;
        byte[]? _peerChallenge;
        byte[]? _ntResponse;

        /// <summary>Creates the state machine for the given credentials.</summary>
        public EapMsChapV2Client(string userName, string password)
        {
            _userName = userName;
            _password = password;
        }

        /// <summary>The 64-byte EAP-MSK, available once the MS-CHAPv2 Success has been verified; null before then.</summary>
        public byte[]? Msk { get; private set; }

        /// <summary>
        /// Processes one inbound EAP packet and produces the peer's EAP response.
        /// <paramref name="responsePacket"/> is the EAP packet to send back, or null when the inbound packet is a
        /// terminal EAP-Success/Failure (nothing to reply).
        /// </summary>
        public EapResult Handle(ReadOnlySpan<byte> eap, out byte[]? responsePacket)
        {
            responsePacket = null;
            if (eap.Length < 4) return EapResult.Failed;

            switch ((EapCode)eap[0])
            {
                case EapCode.Success:
                    return Msk is not null ? EapResult.Success : EapResult.Failed; // valid only after MS-CHAPv2 Success
                case EapCode.Failure:
                    return EapResult.Failed;
                case EapCode.Request:
                    return HandleRequest(eap, eap[1], out responsePacket);
                default:
                    return EapResult.Failed;
            }
        }

        EapResult HandleRequest(ReadOnlySpan<byte> eap, byte id, out byte[]? responsePacket)
        {
            responsePacket = null;
            if (eap.Length < 5) return EapResult.Failed;
            byte type = eap[4];

            if (type == EapTypeIdentity)
            {
                responsePacket = EapPacket.Build(EapCode.Response, id, EapTypeIdentity, Encoding.ASCII.GetBytes(_userName));
                return EapResult.Continue;
            }
            if (type != EapTypeMsChapV2 || eap.Length < 6) return EapResult.Failed;

            switch (eap[5])
            {
                case OpChallenge:
                    return HandleChallenge(eap, id, out responsePacket);
                case OpSuccess:
                    return HandleSuccess(eap, id, out responsePacket);
                case OpFailure:
                    responsePacket = EapPacket.Build(EapCode.Response, id, EapTypeMsChapV2, new byte[] { OpFailure });
                    return EapResult.Failed;
                default:
                    return EapResult.Failed;
            }
        }

        // MS-CHAPv2 Challenge: OpCode(1)=1 | MS-CHAPv2-ID(1) | MS-Length(2) | Value-Size(1)=16 | Challenge(16) | Name…
        EapResult HandleChallenge(ReadOnlySpan<byte> eap, byte id, out byte[]? responsePacket)
        {
            responsePacket = null;
            if (eap.Length < 10) return EapResult.Failed;
            int valueSize = eap[9];
            if (valueSize != 16 || eap.Length < 10 + 16) return EapResult.Failed;
            byte[] authChallenge = eap.Slice(10, 16).ToArray();

            byte[] peerChallenge = new byte[16];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(peerChallenge);
            byte[] ntResponse = MsChapV2.GenerateNTResponse(authChallenge, peerChallenge, _userName, _password);

            _authenticatorChallenge = authChallenge;
            _peerChallenge = peerChallenge;
            _ntResponse = ntResponse;

            responsePacket = EapPacket.Build(EapCode.Response, id, EapTypeMsChapV2, BuildResponseData(peerChallenge, ntResponse));
            return EapResult.Continue;
        }

        // MS-CHAPv2 Response type-data: OpCode=2 | MS-CHAPv2-ID(echo id) | MS-Length(2) | Value-Size(1)=49 |
        //   Response(49) = Peer-Challenge(16) | Reserved(8)=0 | NT-Response(24) | Flags(1)=0 | Name(var).
        byte[] BuildResponseData(byte[] peerChallenge, byte[] ntResponse)
        {
            byte[] value = new byte[49];
            Buffer.BlockCopy(peerChallenge, 0, value, 0, 16);
            Buffer.BlockCopy(ntResponse, 0, value, 24, 24);
            value[48] = 0x00; // Flags

            byte[] name = Encoding.ASCII.GetBytes(_userName);
            int msLength = 4 + 1 + value.Length + name.Length; // OpCode+ID+MS-Length(2) + Value-Size + Value + Name
            byte[] data = new byte[msLength];
            data[0] = OpResponse;
            data[1] = 0; // MS-CHAPv2-ID echoed by the caller via EapPacket id; the inner id is informational here
            data[2] = (byte)(msLength >> 8);
            data[3] = (byte)msLength;
            data[4] = (byte)value.Length;
            Buffer.BlockCopy(value, 0, data, 5, value.Length);
            Buffer.BlockCopy(name, 0, data, 5 + value.Length, name.Length);
            return data;
        }

        // MS-CHAPv2 Success request: OpCode(1)=3 | MS-CHAPv2-ID(1) | MS-Length(2) | Message("S=<hex> M=…").
        EapResult HandleSuccess(ReadOnlySpan<byte> eap, byte id, out byte[]? responsePacket)
        {
            responsePacket = null;
            if (_authenticatorChallenge is null || _peerChallenge is null || _ntResponse is null) return EapResult.Failed;
            if (eap.Length < 9) return EapResult.Failed;

            string message = Encoding.ASCII.GetString(eap.Slice(9).ToArray()); // skip Type, OpCode, MS-CHAPv2-ID, MS-Length
            byte[]? serverDigest = ParseAuthenticatorResponse(message);
            if (serverDigest is null) return EapResult.Failed;

            byte[] expected = MsChapV2.GenerateAuthenticatorResponse(
                _authenticatorChallenge, _peerChallenge, _ntResponse, _userName, _password);
            if (!CryptoBytes.FixedTimeEquals(expected, serverDigest)) return EapResult.Failed;

            Msk = MsChapV2.DeriveMsk(_password, _ntResponse);
            responsePacket = EapPacket.Build(EapCode.Response, id, EapTypeMsChapV2, new byte[] { OpSuccess });
            return EapResult.Continue;
        }

        // Extracts the 20-byte digest from the "S=<40 hex>" field of a Success message (RFC 2759 §8.7).
        static byte[]? ParseAuthenticatorResponse(string message)
        {
            int idx = message.IndexOf("S=", StringComparison.Ordinal);
            if (idx < 0 || message.Length < idx + 2 + 40) return null;
            return FromHex(message.Substring(idx + 2, 40));
        }

        static byte[]? FromHex(string hex)
        {
            if (hex.Length % 2 != 0) return null;
            byte[] result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                int hi = HexValue(hex[i * 2]);
                int lo = HexValue(hex[i * 2 + 1]);
                if (hi < 0 || lo < 0) return null;
                result[i] = (byte)((hi << 4) | lo);
            }
            return result;
        }

        static int HexValue(char c)
            => c >= '0' && c <= '9' ? c - '0'
             : c >= 'A' && c <= 'F' ? c - 'A' + 10
             : c >= 'a' && c <= 'f' ? c - 'a' + 10
             : -1;
    }
}
