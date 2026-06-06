using System.IO;
using System.Net;
using System.Security.Cryptography;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.Drivers.Sstp.Enums;
using TqkLibrary.Vpn.Drivers.Sstp.Models;
using TqkLibrary.Vpn.Ppp;
using TqkLibrary.Vpn.Ppp.Auth;

namespace TqkLibrary.Vpn.Drivers.Sstp
{
    /// <summary>
    /// A complete MS-SSTP client connection: TLS + SSTP control + PPP + MS-CHAPv2 + crypto binding + IPCP.
    /// After <see cref="ConnectAsync"/> the tunnel carries IP traffic via <see cref="PacketChannel"/>.
    /// </summary>
    public sealed class SstpConnection : IDisposable
    {
        readonly SstpTransport _transport;
        readonly uint _magic;
        SstpPppChannel? _channel;
        PppEngine? _engine;
        CancellationTokenSource? _loopCts;

        /// <summary>Creates a connection to the given SSTP server.</summary>
        public SstpConnection(string host, int port = 443, uint magic = 0x1A2B3C4D)
        {
            _transport = new SstpTransport(host, port);
            _magic = magic;
        }

        /// <summary>The L3 packet channel (valid after a successful connect).</summary>
        public IPacketChannel PacketChannel => _engine!.PacketChannel;

        /// <summary>The IP address assigned by the server.</summary>
        public IPAddress AssignedAddress => _engine!.AssignedAddress;

        /// <summary>The DNS server pushed by the server, if any.</summary>
        public IPAddress? AssignedDns => _engine!.AssignedDns;

        /// <summary>Connects and authenticates, returning once IPCP has assigned an address.</summary>
        public async Task ConnectAsync(string userName, string password, CancellationToken cancellationToken = default)
        {
            await _transport.ConnectAsync(cancellationToken).ConfigureAwait(false);

            var encapsulatedProtocol = new SstpAttribute((byte)SstpAttributeId.EncapsulatedProtocolId, new byte[] { 0x00, 0x01 });
            await _transport.SendControlAsync(SstpMessageType.CallConnectRequest, new[] { encapsulatedProtocol }, cancellationToken).ConfigureAwait(false);

            (bool _, byte[] ackBody) = await _transport.ReadPacketAsync(cancellationToken).ConfigureAwait(false);
            SstpControlMessage ack = SstpControlCodec.Parse(ackBody);
            if (ack.MessageType != SstpMessageType.CallConnectAck)
                throw new IOException($"Expected Call Connect Ack, got {ack.MessageType}.");

            SstpAttribute cryptoRequest = ack.Find(SstpAttributeId.CryptoBindingReq)
                ?? throw new IOException("Call Connect Ack has no crypto binding request.");
            byte[] nonce = new byte[32];
            Buffer.BlockCopy(cryptoRequest.Value, 4, nonce, 0, 32); // Reserved(3) + Bitmask(1) + Nonce(32)

            _channel = new SstpPppChannel(_transport);
            _channel.ControlReceived += OnControlReceived;
            var authenticator = new MsChapV2Authenticator(userName, password);
            _engine = new PppEngine(_channel, _magic, IPAddress.Any, authenticator: authenticator);

            _engine.AuthSucceeded += () =>
            {
                byte[] hlak = authenticator.DeriveHlak();
                byte[] certHash;
                using (var sha256 = SHA256.Create())
                    certHash = sha256.ComputeHash(_transport.ServerCertificate!.RawData);
                SstpAttribute cryptoBinding = SstpCryptoBinding.BuildCryptoBinding(hlak, nonce, certHash);
                _ = _transport.SendControlAsync(SstpMessageType.CallConnected, new[] { cryptoBinding }, cancellationToken);
            };

            var linkUp = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _engine.LinkUp += () => linkUp.TrySetResult(true);

            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _ = Task.Run(() => _channel.RunReadLoopAsync(_loopCts.Token));
            _engine.Start();

            await Task.WhenAny(linkUp.Task, Task.Delay(Timeout.Infinite, cancellationToken)).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            await linkUp.Task.ConfigureAwait(false);
        }

        void OnControlReceived(SstpControlMessage message)
        {
            // Keep the tunnel alive: answer the server's periodic Echo Request.
            if (message.MessageType == SstpMessageType.EchoRequest)
                _ = _transport.SendControlAsync(SstpMessageType.EchoResponse, Array.Empty<SstpAttribute>(), _loopCts?.Token ?? CancellationToken.None);
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _loopCts?.Cancel();
            _transport.Dispose();
        }
    }
}
