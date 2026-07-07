using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Drivers.AmneziaWg.Interfaces;
using TqkLibrary.VpnClient.Drivers.AmneziaWg.Models;
using TqkLibrary.VpnClient.Drivers.WireGuard.Transport;

namespace TqkLibrary.VpnClient.Drivers.AmneziaWg
{
    /// <summary>
    /// An <see cref="IWireGuardTransportFactory"/> decorator that layers AmneziaWG obfuscation onto whatever base factory
    /// the WireGuard driver would otherwise use (the production socket factory, or an in-process loopback for tests). It
    /// connects the base transport, then returns a handle whose:
    /// <list type="bullet">
    ///   <item><see cref="WireGuardTransportHandle.Datagram"/> is wrapped in an <see cref="AmneziaWgDatagramTransport"/>
    ///   so outbound WireGuard datagrams are obfuscated (and the Jc junk burst precedes the first initiation);</item>
    ///   <item><see cref="WireGuardTransportHandle.SetReceiver"/> is wrapped so the connection's inbound handler only sees
    ///   de-obfuscated WireGuard datagrams — junk is dropped before it reaches WireGuard;</item>
    ///   <item><see cref="WireGuardTransportHandle.ReceivePump"/> is passed through unchanged (it drives the base
    ///   transport's receive loop, which now delivers into the de-obfuscating wrapper).</item>
    /// </list>
    /// One <see cref="AmneziaWgObfuscator"/> is created per connection and shared by both directions. This is a pure
    /// decorator over the existing WireGuard transport seam: the WireGuard driver and <c>VpnClientBuilder</c> are untouched.
    /// </summary>
    public sealed class AmneziaWgTransportFactory : IWireGuardTransportFactory
    {
        readonly IWireGuardTransportFactory _inner;
        readonly AmneziaWgParameters _parameters;
        readonly IAmneziaWgRandom? _random;

        /// <summary>
        /// Wraps <paramref name="inner"/> (the base WireGuard transport factory) with the obfuscation described by
        /// <paramref name="parameters"/> (validated per connection). <paramref name="random"/> supplies junk bytes/sizes;
        /// null uses the shared cryptographic RNG.
        /// </summary>
        public AmneziaWgTransportFactory(IWireGuardTransportFactory inner, AmneziaWgParameters parameters,
            IAmneziaWgRandom? random = null)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
            _random = random;
        }

        /// <inheritdoc/>
        public async Task<WireGuardTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
        {
            WireGuardTransportHandle baseHandle = await _inner.ConnectAsync(remote, cancellationToken).ConfigureAwait(false);
            var obfuscator = new AmneziaWgObfuscator(_parameters, _random);

            var datagram = new AmneziaWgDatagramTransport(baseHandle.Datagram, obfuscator, ownsInner: true);

            // Register a de-obfuscating wrapper on the base handle: the base receive path delivers raw wire bytes to this
            // wrapper, which restores the WireGuard datagram (or drops junk) before invoking the connection's handler.
            Action<Action<ReadOnlyMemory<byte>>> setReceiver = connectionHandler =>
            {
                baseHandle.SetReceiver(wire =>
                {
                    if (obfuscator.TryDeobfuscate(wire.Span, out byte[] wg))
                        connectionHandler(wg);
                    // else junk ⇒ drop
                });
            };

            return new WireGuardTransportHandle(datagram, setReceiver, baseHandle.ReceivePump);
        }
    }
}
