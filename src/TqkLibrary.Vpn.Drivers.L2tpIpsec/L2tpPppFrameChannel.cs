using TqkLibrary.Vpn.L2tp;
using TqkLibrary.Vpn.Ppp.Interfaces;

namespace TqkLibrary.Vpn.Drivers.L2tpIpsec
{
    /// <summary>Bridges the L2TP data channel to the PPP engine: PPP frames ride in L2TP data messages.</summary>
    public sealed class L2tpPppFrameChannel : IPppFrameChannel
    {
        readonly L2tpClient _l2tp;

        /// <summary>Creates the channel over a connected <see cref="L2tpClient"/>.</summary>
        public L2tpPppFrameChannel(L2tpClient l2tp)
        {
            _l2tp = l2tp;
            _l2tp.DataReceived += frame => FrameReceived?.Invoke(frame);
        }

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? FrameReceived;

        /// <inheritdoc/>
        public ValueTask SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken = default)
            => new ValueTask(_l2tp.SendDataAsync(frame));
    }
}
