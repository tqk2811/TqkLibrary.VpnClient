using TqkLibrary.Vpn.Drivers.Sstp.Models;
using TqkLibrary.Vpn.Ppp.Interfaces;

namespace TqkLibrary.Vpn.Drivers.Sstp
{
    /// <summary>
    /// Bridges the SSTP data channel to the PPP engine. Per [MS-SSTP], the SSTP Length field delineates packets,
    /// so each data packet carries exactly one RAW PPP frame (no HDLC byte-stuffing / FCS). SSTP control packets
    /// are surfaced via <see cref="ControlReceived"/>.
    /// </summary>
    public sealed class SstpPppChannel : IPppFrameChannel
    {
        readonly SstpTransport _transport;

        /// <summary>Creates a channel over the given (already connected) transport.</summary>
        public SstpPppChannel(SstpTransport transport)
        {
            _transport = transport;
        }

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? FrameReceived;

        /// <summary>Raised for each inbound SSTP control message (Call Connected ack, Abort, Echo...).</summary>
        public event Action<SstpControlMessage>? ControlReceived;

        /// <summary>Number of SSTP data packets received (diagnostic).</summary>
        public int DataPacketsReceived { get; private set; }

        /// <summary>Number of SSTP control packets received (diagnostic).</summary>
        public int ControlPacketsReceived { get; private set; }

        /// <summary>The exception that terminated the read loop, if any (diagnostic).</summary>
        public Exception? ReadError { get; private set; }

        /// <inheritdoc/>
        public ValueTask SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken = default)
            => new ValueTask(_transport.SendDataAsync(frame, cancellationToken));

        /// <summary>Reads SSTP packets until cancelled, dispatching data to PPP and control to <see cref="ControlReceived"/>.</summary>
        public async Task RunReadLoopAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    (bool isControl, byte[] body) = await _transport.ReadPacketAsync(cancellationToken).ConfigureAwait(false);
                    if (isControl)
                    {
                        ControlPacketsReceived++;
                        ControlReceived?.Invoke(SstpControlCodec.Parse(body));
                    }
                    else
                    {
                        DataPacketsReceived++;
                        FrameReceived?.Invoke(body);
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                ReadError = ex;
            }
        }
    }
}
