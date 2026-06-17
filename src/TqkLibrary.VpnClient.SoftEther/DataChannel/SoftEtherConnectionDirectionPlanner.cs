using System.Collections.Generic;
using TqkLibrary.VpnClient.SoftEther.DataChannel.Enums;

namespace TqkLibrary.VpnClient.SoftEther.DataChannel
{
    /// <summary>
    /// Decides the per-connection <see cref="SoftEtherConnectionDirection"/> for a multi-connection session given the
    /// connection count and whether the session is half-duplex. Pure (no I/O, no state) — split out so the wire-facing
    /// decision is unit-testable and shared by the driver.
    /// <list type="bullet">
    /// <item>Full-duplex (<paramref name="halfConnection"/> = <c>false</c>): every connection is
    /// <see cref="SoftEtherConnectionDirection.Both"/>.</item>
    /// <item>Half-duplex: the connections are split as evenly as possible into send-only and receive-only, always
    /// keeping at least one of each (so a single connection stays <see cref="SoftEtherConnectionDirection.Both"/> —
    /// half-duplex is meaningless with one socket). The first half send, the rest receive, matching the client's
    /// convention of dedicating the lower-indexed sockets to upstream.</item>
    /// </list>
    /// </summary>
    public static class SoftEtherConnectionDirectionPlanner
    {
        /// <summary>
        /// Returns the directions for <paramref name="connectionCount"/> connections. With <paramref name="halfConnection"/>
        /// and ≥2 connections, the first <c>floor(n/2)</c> (at least 1) are <see cref="SoftEtherConnectionDirection.Send"/>
        /// and the rest <see cref="SoftEtherConnectionDirection.Receive"/>; otherwise all are
        /// <see cref="SoftEtherConnectionDirection.Both"/>.
        /// </summary>
        public static SoftEtherConnectionDirection[] Plan(int connectionCount, bool halfConnection)
        {
            if (connectionCount < 1)
                throw new ArgumentOutOfRangeException(nameof(connectionCount), "At least one connection is required.");

            var directions = new SoftEtherConnectionDirection[connectionCount];
            if (!halfConnection || connectionCount < 2)
                return directions;   // all Both (enum default 0)

            int sendCount = connectionCount / 2;          // floor; at least 1 because count ≥ 2
            for (int i = 0; i < connectionCount; i++)
                directions[i] = i < sendCount ? SoftEtherConnectionDirection.Send : SoftEtherConnectionDirection.Receive;
            return directions;
        }
    }
}
