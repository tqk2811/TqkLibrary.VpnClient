using TqkLibrary.VpnClient.OpenVpn.DataChannel;

namespace TqkLibrary.VpnClient.OpenVpn.Transport
{
    /// <summary>
    /// Shared plumbing for the two OpenVPN data-channel link bridges (V2.g): it threads a tunnelled payload — a bare IP
    /// packet for tun, a full Ethernet frame for tap — through compression framing (<see cref="OpenVpnCompression"/>)
    /// and the AEAD data plane (<see cref="OpenVpnDataPlane"/>) to an outbound sink, and inbound recovers a payload from
    /// a wire packet the driver hands it via <see cref="Deliver"/>. The data channel itself is payload-agnostic — only
    /// the channel medium differs (<see cref="OpenVpnTunChannel"/> = L3 <c>IPacketChannel</c>,
    /// <see cref="OpenVpnTapChannel"/> = L2 <c>IEthernetChannel</c> for the Ethernet fabric), which the subclasses
    /// supply. The <paramref name="sink"/> is the transport send (a UDP send, or <see cref="OpenVpnTcpTransport.SendAsync"/>);
    /// the driver routes only post-demux P_DATA packets into <see cref="Deliver"/>.
    /// </summary>
    public abstract class OpenVpnDataLink : IAsyncDisposable
    {
        readonly OpenVpnDataPlane _dataPlane;
        readonly OpenVpnCompression _compression;
        readonly Func<ReadOnlyMemory<byte>, ValueTask> _sink;

        /// <summary>Wires the bridge to a data plane, compression codec and outbound transport sink.</summary>
        protected OpenVpnDataLink(OpenVpnDataPlane dataPlane, OpenVpnCompression compression, Func<ReadOnlyMemory<byte>, ValueTask> sink)
        {
            _dataPlane = dataPlane ?? throw new ArgumentNullException(nameof(dataPlane));
            _compression = compression ?? throw new ArgumentNullException(nameof(compression));
            _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        }

        /// <summary>Compression-frames + seals a tunnelled payload, then pushes the data packet to the transport sink.</summary>
        protected ValueTask SendPayloadAsync(ReadOnlySpan<byte> payload)
        {
            byte[] framed = _compression.WrapOutgoing(payload);
            byte[] wire = _dataPlane.Protect(framed);
            return _sink(wire);
        }

        /// <summary>
        /// Recovers the tunnelled payload from one inbound data-channel wire packet (the driver routes P_DATA here after
        /// opcode demux). Returns false if the AEAD/replay check or compression de-framing rejects it.
        /// </summary>
        protected bool TryReceivePayload(ReadOnlySpan<byte> wire, out byte[] payload)
        {
            payload = Array.Empty<byte>();
            if (!_dataPlane.TryUnprotect(wire, out byte[] framed)) return false;
            if (!_compression.TryUnwrapIncoming(framed, out payload)) return false;
            // An OpenVPN keepalive ping rides the data channel like any payload but is liveness signalling, not user
            // traffic — it must never reach the IP/Ethernet layer, so drop it here (the driver still counts the inbound
            // data packet toward keepalive before delegating to Deliver).
            if (OpenVpnPing.IsPing(payload)) { payload = Array.Empty<byte>(); return false; }
            return true;
        }

        /// <summary>Routes one inbound data-channel wire packet to the channel's inbound event (raises nothing if dropped).</summary>
        public abstract void Deliver(ReadOnlySpan<byte> wire);

        /// <inheritdoc/>
        public virtual ValueTask DisposeAsync() => default;
    }
}
