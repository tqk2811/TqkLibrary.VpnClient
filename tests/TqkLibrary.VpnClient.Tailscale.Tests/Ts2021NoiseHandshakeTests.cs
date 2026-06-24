using System;
using System.Text;
using TqkLibrary.VpnClient.Crypto.Aead;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Tailscale.Control.Noise;
using Xunit;

namespace TqkLibrary.VpnClient.Tailscale.Tests
{
    /// <summary>
    /// Self-pair tests for the ts2021 Noise IK initiator against a minimal in-test IK responder built directly on
    /// <see cref="NoiseSymmetricState"/> (the same engine the production handshake drives). Confirms the IK token order
    /// interoperates and both sides derive matching transport keys (initiator send = responder receive).
    /// </summary>
    public class Ts2021NoiseHandshakeTests
    {
        // A minimal IK responder mirroring control/controlbase: pre-message <- s, msg1 -> e,es,s,ss, msg2 <- e,ee,se.
        sealed class IkResponder
        {
            readonly Curve25519DhGroup _dh = new Curve25519DhGroup();
            readonly NoiseSymmetricState _state = new NoiseSymmetricState(new HmacBlake2sPrf(), new Blake2s(), new ChaCha20Poly1305Cipher());
            readonly byte[] _staticPrivate;
            readonly byte[] _staticPublic;
            readonly string _prologue;
            byte[]? _ephemeralPrivate;
            byte[]? _remoteEphemeralPublic;
            byte[]? _remoteStaticPublic;

            public IkResponder(byte[] staticPrivate, int protocolVersion)
            {
                _staticPrivate = staticPrivate;
                _staticPublic = _dh.DerivePublicValue(staticPrivate);
                _prologue = "Tailscale Control Protocol v" + protocolVersion;
            }

            public byte[] StaticPublic => _staticPublic;

            void Initialize()
            {
                _state.InitializeSymmetric(Encoding.ASCII.GetBytes("Noise_IK_25519_ChaChaPoly_BLAKE2s"));
                _state.MixHash(Encoding.ASCII.GetBytes(_prologue));
                _state.MixHash(_staticPublic); // IK pre-message: <- s (responder static)
            }

            public bool ConsumeInitiation(ReadOnlySpan<byte> message, out byte[] payload)
            {
                payload = Array.Empty<byte>();
                Initialize();
                if (message.Length < 32) return false;
                _remoteEphemeralPublic = message.Slice(0, 32).ToArray();
                _state.MixHash(_remoteEphemeralPublic);                                               // e
                _state.MixKey(_dh.DeriveSharedSecret(_staticPrivate, _remoteEphemeralPublic));        // es: DH(s_r, e_i)
                byte[]? s = _state.DecryptAndHash(message.Slice(32, 48));                             // s (32 + 16 tag)
                if (s is null) return false;
                _remoteStaticPublic = s;
                _state.MixKey(_dh.DeriveSharedSecret(_staticPrivate, _remoteStaticPublic));           // ss: DH(s_r, s_i)
                byte[]? p = _state.DecryptAndHash(message.Slice(32 + 48));                            // payload
                if (p is null) return false;
                payload = p;
                return true;
            }

            public byte[] CreateResponse(ReadOnlySpan<byte> payload)
            {
                _ephemeralPrivate = _dh.GeneratePrivateKey();
                byte[] ePub = _dh.DerivePublicValue(_ephemeralPrivate);
                _state.MixHash(ePub);                                                                 // e
                _state.MixKey(_dh.DeriveSharedSecret(_ephemeralPrivate, _remoteEphemeralPublic!));    // ee
                _state.MixKey(_dh.DeriveSharedSecret(_ephemeralPrivate, _remoteStaticPublic!));       // se: DH(e_r, s_i)
                byte[] sealedPayload = _state.EncryptAndHash(payload);
                byte[] result = new byte[ePub.Length + sealedPayload.Length];
                Buffer.BlockCopy(ePub, 0, result, 0, ePub.Length);
                Buffer.BlockCopy(sealedPayload, 0, result, ePub.Length, sealedPayload.Length);
                return result;
            }

            public (byte[] SendKey, byte[] ReceiveKey) Split()
            {
                (byte[] first, byte[] second) = _state.Split();
                return (second, first); // responder swaps
            }
        }

        [Fact]
        public void IkSelfPair_CompletesAndDerivesMatchingKeys()
        {
            var dh = new Curve25519DhGroup();
            byte[] clientStatic = dh.GeneratePrivateKey();
            byte[] serverStatic = dh.GeneratePrivateKey();
            byte[] serverStaticPub = dh.DerivePublicValue(serverStatic);

            var responder = new IkResponder(serverStatic, 1);
            var initiator = new Ts2021NoiseHandshake(clientStatic, serverStaticPub, 1);

            byte[] msg1 = initiator.CreateInitiation(Array.Empty<byte>());
            Assert.True(responder.ConsumeInitiation(msg1, out _));

            byte[] msg2 = responder.CreateResponse(Array.Empty<byte>());
            Assert.True(initiator.ConsumeResponse(msg2, out _));
            Assert.True(initiator.IsCompleted);

            (byte[] cSend, byte[] cRecv) = initiator.Split();
            (byte[] sSend, byte[] sRecv) = responder.Split();

            // Initiator send key == responder receive key, and vice versa.
            Assert.Equal(cSend, sRecv);
            Assert.Equal(cRecv, sSend);
        }

        [Fact]
        public void Initiation_HasExpectedLength_E32_S48_EmptyPayloadTag16()
        {
            var dh = new Curve25519DhGroup();
            byte[] clientStatic = dh.GeneratePrivateKey();
            byte[] serverStaticPub = dh.DerivePublicValue(dh.GeneratePrivateKey());
            var initiator = new Ts2021NoiseHandshake(clientStatic, serverStaticPub, 1);
            byte[] msg1 = initiator.CreateInitiation(Array.Empty<byte>());
            // e(32) + enc(s)+tag(48) + enc(empty)+tag(16) = 96
            Assert.Equal(96, msg1.Length);
        }

        [Fact]
        public void ConsumeResponse_TamperedPayload_Fails()
        {
            var dh = new Curve25519DhGroup();
            byte[] clientStatic = dh.GeneratePrivateKey();
            byte[] serverStatic = dh.GeneratePrivateKey();
            byte[] serverStaticPub = dh.DerivePublicValue(serverStatic);

            var responder = new IkResponder(serverStatic, 1);
            var initiator = new Ts2021NoiseHandshake(clientStatic, serverStaticPub, 1);
            byte[] msg1 = initiator.CreateInitiation(Array.Empty<byte>());
            responder.ConsumeInitiation(msg1, out _);
            byte[] msg2 = responder.CreateResponse(Array.Empty<byte>());
            msg2[msg2.Length - 1] ^= 0xFF; // flip the last tag byte

            Assert.False(initiator.ConsumeResponse(msg2, out _));
        }
    }
}
