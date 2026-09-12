using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.IpStack.Udp;
using TqkLibrary.VpnClient.Tunnels.Interfaces;

namespace TqkLibrary.VpnClient.Tunnels
{
    /// <summary>
    /// Proves a tunnel still carries traffic by sending through its own stack: an ICMP echo first,
    /// and a DNS question when that goes unanswered.
    /// </summary>
    /// <remarks>
    /// Two probes because neither alone is trustworthy. Ping is a single small packet and costs
    /// nothing, but plenty of VPN servers drop ICMP inside the tunnel on principle — believing that
    /// silence would declare a perfectly good tunnel dead every twenty seconds. A DNS question is
    /// heavier but it is answered by any server worth dialling, and it is the exact thing the host
    /// needs to work anyway: the failure this whole class exists to catch showed up first as name
    /// lookups timing out. ANY reply counts, including a refusal or an empty answer — the question
    /// is whether packets cross the tunnel, not what the answer says.
    /// </remarks>
    public sealed class IpStackTunnelProbe : ITunnelProbe
    {
        // Asked about rather than resolved: it exists, every resolver answers for it, and its
        // records are so long-lived that the answer comes from cache instead of a recursion.
        const string ProbeName = "a.root-servers.net";

        // Where to aim when the VPN handed out no DNS server of its own. Reachable from nearly
        // every exit, and still inside the tunnel, so it leaks nothing.
        static readonly IPAddress FallbackTarget = IPAddress.Parse("1.1.1.1");

        readonly TcpIpStack _stack;
        readonly IPAddress _target;
        readonly TimeSpan _timeout;
        readonly ILogger _logger;
        int _nextId;

        /// <param name="stack">The tunnel's own stack — the probe must travel inside the tunnel.</param>
        /// <param name="target">The DNS server the VPN assigned; null aims at a public resolver instead.</param>
        /// <param name="timeout">How long each half of the probe waits before giving up.</param>
        /// <param name="logger">Where probe outcomes are traced; null logs nowhere.</param>
        public IpStackTunnelProbe(TcpIpStack stack, IPAddress? target, TimeSpan timeout, ILogger? logger = null)
        {
            _stack = stack ?? throw new ArgumentNullException(nameof(stack));
            _target = target ?? FallbackTarget;
            _timeout = timeout;
            _logger = logger ?? NullLogger.Instance;
        }

        /// <summary>Where the probes are aimed. Diagnostics only.</summary>
        public IPAddress Target => _target;

        /// <inheritdoc/>
        public async Task<bool> IsAliveAsync(CancellationToken cancellationToken)
        {
            if (await PingAsync(cancellationToken).ConfigureAwait(false)) return true;
            return await AskDnsAsync(cancellationToken).ConfigureAwait(false);
        }

        async Task<bool> PingAsync(CancellationToken cancellationToken)
        {
            using CancellationTokenSource timeout = Deadline(cancellationToken);
            try
            {
                await _stack.PingAsync(_target, default, timeout.Token).ConfigureAwait(false);
                return true;
            }
            catch (IcmpUnreachableException)
            {
                // An answer all the same: something inside the tunnel received the packet and had
                // an opinion about it. The tunnel carries traffic, which is the only question here.
                return true;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogTrace(ex, "tunnel probe: ping to {Target} failed outright", _target);
                return false;
            }
        }

        async Task<bool> AskDnsAsync(CancellationToken cancellationToken)
        {
            ushort id = (ushort)Interlocked.Increment(ref _nextId);
            UdpConnection socket = _stack.BindUdp();
            using CancellationTokenSource timeout = Deadline(cancellationToken);
            try
            {
                socket.SendTo(_target, 53, BuildQuery(ProbeName, id));
                UdpReceiveResult reply = await socket.ReceiveAsync(timeout.Token).ConfigureAwait(false);

                // Only the transaction id is checked. Whether the answer carries records, a refusal
                // or an error is the resolver's business; that it arrived at all is ours.
                return reply.Data.Length >= 2 && (ushort)((reply.Data[0] << 8) | reply.Data[1]) == id;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogTrace(ex, "tunnel probe: dns question to {Target} failed outright", _target);
                return false;
            }
            finally
            {
                _stack.UnbindUdp(socket.LocalPort);
            }
        }

        CancellationTokenSource Deadline(CancellationToken cancellationToken)
        {
            CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(_timeout);
            return cts;
        }

        // A minimal query: one question, recursion desired, no additional records.
        static byte[] BuildQuery(string name, ushort id)
        {
            string[] labels = name.Split('.');
            int length = 12 + 1 + 4;
            foreach (string label in labels) length += 1 + label.Length;

            byte[] message = new byte[length];
            message[0] = (byte)(id >> 8);
            message[1] = (byte)id;
            message[2] = 0x01;   // recursion desired
            message[5] = 0x01;   // one question

            int offset = 12;
            foreach (string label in labels)
            {
                message[offset++] = (byte)label.Length;
                foreach (char c in label) message[offset++] = (byte)c;
            }

            message[offset++] = 0;      // root label
            message[offset++] = 0;
            message[offset++] = 1;      // QTYPE A
            message[offset++] = 0;
            message[offset] = 1;        // QCLASS IN
            return message;
        }
    }
}
