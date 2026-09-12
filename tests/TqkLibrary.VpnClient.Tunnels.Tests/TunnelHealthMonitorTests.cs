using TqkLibrary.VpnClient.Tunnels;
using TqkLibrary.VpnClient.Tunnels.Interfaces;
using Xunit;

namespace TqkLibrary.VpnClient.Tunnels.Tests;

// What a driver cannot detect for itself: a server that keeps the transport up and quietly stops
// carrying the session. Everything here turns on the monitor counting SILENCE rather than trusting
// a state flag, so each test drives the probe and the up-flag independently.
public class TunnelHealthMonitorTests
{
    static VpnHealthProbeOptions FastOptions(int failures = 3) => new VpnHealthProbeOptions
    {
        Interval = TimeSpan.FromMilliseconds(20),
        Timeout = TimeSpan.FromMilliseconds(50),
        FailuresBeforeDead = failures,
    };

    [Fact]
    public async Task ATunnelThatKeepsAnswering_IsNeverDeclaredDead()
    {
        var probe = new FakeProbe(alive: true);
        var verdicts = new List<string>();

        await using var monitor = new TunnelHealthMonitor(
            probe, () => true, verdicts.Add, FastOptions(), "test");
        monitor.Start();

        await probe.WaitForCallsAsync(5);

        Assert.Empty(verdicts);
    }

    [Fact]
    public async Task SilenceForTheWholeBudget_DeclaresTheLinkDeadOnce()
    {
        var probe = new FakeProbe(alive: false);
        var dead = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        int verdicts = 0;

        await using var monitor = new TunnelHealthMonitor(
            probe,
            () => true,
            reason => { Interlocked.Increment(ref verdicts); dead.TrySetResult(reason); },
            FastOptions(failures: 3), "test");
        monitor.Start();

        string reason = await dead.Task.WaitAsync(TimeSpan.FromSeconds(5));

        // Three probes bought the verdict, not one: a single lost datagram must not re-dial a tunnel.
        Assert.True(probe.Calls >= 3);
        Assert.Contains("nothing crosses it", reason);
        Assert.Equal(1, verdicts);
    }

    [Fact]
    public async Task AnAnswerAfterSomeSilence_StartsTheCountOver()
    {
        // Silent twice, then answering for good: two short of the budget every time round, so the
        // verdict must never come — this is the lossy-path case, not a dead tunnel.
        var probe = new FakeProbe(alive: false);
        var verdicts = new List<string>();

        await using var monitor = new TunnelHealthMonitor(
            probe, () => true, verdicts.Add, FastOptions(failures: 3), "test");
        monitor.Start();

        await probe.WaitForCallsAsync(2);
        probe.Alive = true;
        await probe.WaitForCallsAsync(probe.Calls + 6);

        Assert.Empty(verdicts);
    }

    [Fact]
    public async Task WhileTheDriverSaysTheTunnelIsDown_NothingIsProbedOrReported()
    {
        var probe = new FakeProbe(alive: false);
        var verdicts = new List<string>();

        await using var monitor = new TunnelHealthMonitor(
            probe, () => false, verdicts.Add, FastOptions(failures: 1), "test");
        monitor.Start();

        // Long enough for a dozen intervals: a driver that is already mending its own link must not
        // be told to start over on the strength of probes against a link that is not there yet.
        await Task.Delay(TimeSpan.FromMilliseconds(300));

        Assert.Equal(0, probe.Calls);
        Assert.Empty(verdicts);
    }

    [Fact]
    public async Task AProbeThatThrows_CountsAsSilence()
    {
        var probe = new FakeProbe(alive: false) { Throw = true };
        var dead = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var monitor = new TunnelHealthMonitor(
            probe, () => true, reason => dead.TrySetResult(reason), FastOptions(failures: 2), "test");
        monitor.Start();

        string reason = await dead.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Contains("nothing crosses it", reason);
    }

    [Fact]
    public async Task AfterDispose_TheLoopStops()
    {
        var probe = new FakeProbe(alive: true);
        var monitor = new TunnelHealthMonitor(probe, () => true, _ => { }, FastOptions(), "test");
        monitor.Start();

        await probe.WaitForCallsAsync(2);
        await monitor.DisposeAsync();

        int settled = probe.Calls;
        await Task.Delay(TimeSpan.FromMilliseconds(200));

        Assert.Equal(settled, probe.Calls);
    }

    [Fact]
    public async Task ReportingTheVerdictIsResumed_WhenTheTunnelGoesSilentAgain()
    {
        // The count resets after a verdict, so a driver whose reconnect lands on an equally dead
        // session is told a second time rather than once and never again.
        var probe = new FakeProbe(alive: false);
        int verdicts = 0;
        var twice = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var monitor = new TunnelHealthMonitor(
            probe,
            () => true,
            _ => { if (Interlocked.Increment(ref verdicts) >= 2) twice.TrySetResult(true); },
            FastOptions(failures: 2), "test");
        monitor.Start();

        await twice.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(verdicts >= 2);
    }

    sealed class FakeProbe : ITunnelProbe
    {
        readonly object _lock = new object();
        TaskCompletionSource<bool>? _waiter;
        int _wantedCalls;
        int _calls;

        public FakeProbe(bool alive) => Alive = alive;

        public volatile bool Alive;

        public bool Throw { get; set; }

        public int Calls => Volatile.Read(ref _calls);

        public Task<bool> IsAliveAsync(CancellationToken cancellationToken)
        {
            lock (_lock)
            {
                _calls++;
                if (_waiter is not null && _calls >= _wantedCalls) _waiter.TrySetResult(true);
            }

            if (Throw) throw new InvalidOperationException("the stack is gone");
            return Task.FromResult(Alive);
        }

        public async Task WaitForCallsAsync(int count)
        {
            Task wait;
            lock (_lock)
            {
                if (_calls >= count) return;
                _wantedCalls = count;
                _waiter = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                wait = _waiter.Task;
            }

            await wait.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }
}
