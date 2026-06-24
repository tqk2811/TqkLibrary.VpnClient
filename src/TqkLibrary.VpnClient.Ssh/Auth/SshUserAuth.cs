using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Ssh.Wire;
using TqkLibrary.VpnClient.Ssh.Wire.Enums;

namespace TqkLibrary.VpnClient.Ssh.Auth
{
    /// <summary>
    /// SSH user authentication (RFC 4252) over an established (post-NEWKEYS) transport: it requests the
    /// <c>ssh-userauth</c> service then authenticates with either the <c>publickey</c> (ed25519) or <c>password</c>
    /// method, both for the <c>ssh-connection</c> service. For publickey the client signs
    /// <c>string session_id || the USERAUTH_REQUEST up to and including the public key blob</c> with its Ed25519 key
    /// (RFC 4252 §7); a single round-trip "true" request carries the signature directly (no preliminary query). Reads and
    /// writes go through the supplied packet-send / packet-read delegates so this layer owns no sockets.
    /// </summary>
    public sealed class SshUserAuth
    {
        const string ServiceConnection = "ssh-connection";
        const string ServiceUserAuth = "ssh-userauth";
        const string Ed25519 = "ssh-ed25519";

        readonly Func<ReadOnlyMemory<byte>, CancellationToken, Task> _send;
        readonly Func<CancellationToken, Task<byte[]>> _read;
        readonly byte[] _sessionId;

        /// <summary>
        /// Wraps the transport. <paramref name="sendPacket"/> frames+encrypts one SSH message payload;
        /// <paramref name="readPacket"/> reads the next decrypted payload; <paramref name="sessionId"/> is the first
        /// exchange hash (signed in the publickey method).
        /// </summary>
        public SshUserAuth(Func<ReadOnlyMemory<byte>, CancellationToken, Task> sendPacket,
            Func<CancellationToken, Task<byte[]>> readPacket, byte[] sessionId)
        {
            _send = sendPacket ?? throw new ArgumentNullException(nameof(sendPacket));
            _read = readPacket ?? throw new ArgumentNullException(nameof(readPacket));
            _sessionId = sessionId ?? throw new ArgumentNullException(nameof(sessionId));
        }

        /// <summary>Sends SSH_MSG_SERVICE_REQUEST("ssh-userauth") and waits for the matching SSH_MSG_SERVICE_ACCEPT.</summary>
        public async Task RequestUserAuthServiceAsync(CancellationToken cancellationToken)
        {
            var w = new SshWriter();
            w.WriteByte((byte)SshMessageNumber.ServiceRequest);
            w.WriteString(ServiceUserAuth);
            await _send(w.ToArray(), cancellationToken).ConfigureAwait(false);

            byte[] reply = await ReadSkippingChatterAsync(cancellationToken).ConfigureAwait(false);
            if (reply.Length == 0 || reply[0] != (byte)SshMessageNumber.ServiceAccept)
                throw new SshProtocolException($"Expected SSH_MSG_SERVICE_ACCEPT, got message {(reply.Length > 0 ? reply[0] : 0)}.");
        }

        /// <summary>
        /// Authenticates with the <c>publickey</c> method using an Ed25519 key. <paramref name="username"/> is the login
        /// user; <paramref name="privateKey"/> is the 32-byte Ed25519 seed. Returns true on SSH_MSG_USERAUTH_SUCCESS,
        /// false on USERAUTH_FAILURE.
        /// </summary>
        public async Task<bool> AuthenticatePublicKeyAsync(string username, byte[] privateKey, CancellationToken cancellationToken)
        {
            var signer = new Ed25519Signer();
            byte[] publicKey = signer.DerivePublicKey(privateKey);

            // Public-key blob: string "ssh-ed25519" || string pubkey.
            var keyBlobW = new SshWriter();
            keyBlobW.WriteString(Ed25519);
            keyBlobW.WriteString(publicKey);
            byte[] keyBlob = keyBlobW.ToArray();

            // The request up to and including the public-key blob (with the signature-present flag = true).
            var reqW = new SshWriter();
            reqW.WriteByte((byte)SshMessageNumber.UserAuthRequest);
            reqW.WriteString(username);
            reqW.WriteString(ServiceConnection);
            reqW.WriteString("publickey");
            reqW.WriteBoolean(true);          // a signature is present
            reqW.WriteString(Ed25519);        // public-key algorithm name
            reqW.WriteString(keyBlob);        // public-key blob
            byte[] requestSoFar = reqW.ToArray();

            // Signed data = string session_id || requestSoFar (RFC 4252 §7).
            var signedW = new SshWriter();
            signedW.WriteString(_sessionId);
            signedW.WriteRaw(requestSoFar);
            byte[] signature = signer.Sign(privateKey, signedW.ToArray());

            // Signature blob: string "ssh-ed25519" || string signature.
            var sigBlobW = new SshWriter();
            sigBlobW.WriteString(Ed25519);
            sigBlobW.WriteString(signature);

            var fullW = new SshWriter();
            fullW.WriteRaw(requestSoFar);
            fullW.WriteString(sigBlobW.ToArray());
            await _send(fullW.ToArray(), cancellationToken).ConfigureAwait(false);

            return await ReadAuthResultAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Authenticates with the <c>password</c> method. <paramref name="username"/> / <paramref name="password"/> are
        /// the credentials. Returns true on SSH_MSG_USERAUTH_SUCCESS, false on USERAUTH_FAILURE (this minimal client does
        /// not handle a password-change request — that surfaces as false).
        /// </summary>
        public async Task<bool> AuthenticatePasswordAsync(string username, string password, CancellationToken cancellationToken)
        {
            var w = new SshWriter();
            w.WriteByte((byte)SshMessageNumber.UserAuthRequest);
            w.WriteString(username);
            w.WriteString(ServiceConnection);
            w.WriteString("password");
            w.WriteBoolean(false);            // not a password change
            w.WriteString(password);
            await _send(w.ToArray(), cancellationToken).ConfigureAwait(false);

            return await ReadAuthResultAsync(cancellationToken).ConfigureAwait(false);
        }

        async Task<bool> ReadAuthResultAsync(CancellationToken cancellationToken)
        {
            byte[] msg = await ReadSkippingChatterAsync(cancellationToken).ConfigureAwait(false);
            if (msg.Length == 0) throw new SshProtocolException("Empty userauth reply.");
            switch ((SshMessageNumber)msg[0])
            {
                case SshMessageNumber.UserAuthSuccess: return true;
                case SshMessageNumber.UserAuthFailure: return false;
                case SshMessageNumber.UserAuthPkOk: return false; // a query-OK without our combined request — treat as not-yet-authenticated
                default: throw new SshProtocolException($"Unexpected userauth reply message {msg[0]}.");
            }
        }

        // Skip transport-level chatter (USERAUTH_BANNER, IGNORE, DEBUG, GLOBAL_REQUEST) between meaningful replies.
        async Task<byte[]> ReadSkippingChatterAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                byte[] msg = await _read(cancellationToken).ConfigureAwait(false);
                if (msg.Length == 0) continue;
                switch ((SshMessageNumber)msg[0])
                {
                    case SshMessageNumber.UserAuthBanner:
                    case SshMessageNumber.Ignore:
                    case SshMessageNumber.Debug:
                        continue;
                    case SshMessageNumber.Disconnect:
                        throw new SshProtocolException("SSH server sent DISCONNECT during user authentication.");
                    default:
                        return msg;
                }
            }
        }
    }
}
