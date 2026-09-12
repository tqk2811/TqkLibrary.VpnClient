using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TqkLibrary.VpnClient.Tunnels.Interfaces;

namespace TqkLibrary.VpnClient.Tunnels
{
    /// <summary>
    /// Watches a tunnel that claims to be up and declares it dead once it stops carrying traffic.
    /// </summary>
    /// <remarks>
    /// A driver only ever notices a drop its own protocol tells it about. L2TP/IPsec gets a CDN or
    /// an IKE Delete and reconnects within seconds; SSTP and SoftEther get nothing at all, so a
    /// server that expires the session — which public servers do after a few minutes — leaves the
    /// driver sitting at Connected while every packet through it vanishes. Nothing short of sending
    /// a real packet and waiting for it separates that from a healthy idle tunnel, which is what
    /// this loop does.
    ///
    /// It only counts silence while the tunnel says it is up: a driver already re-establishing its
    /// own link is mending exactly what a probe would report, and racing it would pull the tunnel
    /// down mid-repair.
    /// </remarks>
    public sealed class TunnelHealthMonitor : IAsyncDisposable
    {
        readonly ITunnelProbe _probe;
        readonly Func<bool> _isUp;
        readonly Action<string> _onDead;
        readonly VpnHealthProbeOptions _options;
        readonly ILogger _logger;
        readonly string _name;
        readonly CancellationTokenSource _cts = new CancellationTokenSource();
        Task? _loop;

        /// <param name="probe">What asks the tunnel to prove itself.</param>
        /// <param name="isUp">Whether the driver currently believes the tunnel is up.</param>
        /// <param name="onDead">Called once per verdict, on this loop's thread; must not block it.</param>
        /// <param name="options">Interval, timeout and how many silences make a verdict.</param>
        /// <param name="name">The driver's name, for logs.</param>
        /// <param name="logger">Where probe outcomes are traced; null logs nowhere.</param>
        public TunnelHealthMonitor(
            ITunnelProbe probe, Func<bool> isUp, Action<string> onDead,
            VpnHealthProbeOptions options, string name, ILogger? logger = null)
        {
            _probe = probe ?? throw new ArgumentNullException(nameof(probe));
            _isUp = isUp ?? throw new ArgumentNullException(nameof(isUp));
            _onDead = onDead ?? throw new ArgumentNullException(nameof(onDead));
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _name = name ?? throw new ArgumentNullException(nameof(name));
            _logger = logger ?? NullLogger.Instance;
        }

        /// <summary>Starts probing. Calling it twice is a no-op.</summary>
        public void Start()
        {
            if (_loop is not null) return;
            _loop = Task.Run(() => RunAsync(_cts.Token));
        }

        async Task RunAsync(CancellationToken cancellationToken)
        {
            int silences = 0;

            while (!cancellationToken.IsCancellationRequested)
            {
                try { await Task.Delay(_options.Interval, cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }

                // Down already, by the driver's own reckoning: nothing here to add, and the count
                // starts over so a reconnect is not judged on silence from before it.
                if (!_isUp()) { silences = 0; continue; }

                bool alive;
                try
                {
                    alive = await _probe.IsAliveAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    // A probe that throws has told us nothing about the tunnel, only about itself.
                    // Counting it as silence is the safe reading: a stack that cannot even send is
                    // not carrying traffic either.
                    _logger.LogTrace(ex, "[{Driver}] tunnel probe failed", _name);
                    alive = false;
                }

                if (alive)
                {
                    if (silences > 0)
                        _logger.LogDebug("[{Driver}] tunnel answered again after {Silences} silent probe(s)", _name, silences);
                    silences = 0;
                    continue;
                }

                if (++silences < _options.FailuresBeforeDead)
                {
                    _logger.LogDebug(
                        "[{Driver}] tunnel did not answer probe {Silence}/{Limit}",
                        _name, silences, _options.FailuresBeforeDead);
                    continue;
                }

                // Reset before reporting: the driver reconnects on this, and the next attempt has
                // to be judged on its own silences rather than inheriting these.
                silences = 0;
                try
                {
                    _onDead(
                        $"no answer to {_options.FailuresBeforeDead} probe(s) through the tunnel "
                        + $"over {(int)(_options.FailuresBeforeDead * _options.Interval.TotalSeconds)}s; "
                        + "the transport is still up but nothing crosses it");
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[{Driver}] reporting a dead tunnel threw", _name);
                }
            }
        }

        /// <summary>Stops probing and waits for the loop to unwind.</summary>
        public async ValueTask DisposeAsync()
        {
            _cts.Cancel();
            Task? loop = _loop;
            if (loop is not null)
            {
                try { await loop.ConfigureAwait(false); } catch { /* teardown */ }
            }
            _cts.Dispose();
        }
    }
}
