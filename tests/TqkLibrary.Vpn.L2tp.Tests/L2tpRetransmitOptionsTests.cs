using Xunit;

namespace TqkLibrary.Vpn.L2tp.Tests
{
    public class L2tpRetransmitOptionsTests
    {
        [Fact]
        public void Defaults_ReproduceFixedIntervalNoBackoff()
        {
            var options = new L2tpRetransmitOptions();

            Assert.Equal(TimeSpan.FromSeconds(1), options.Interval);
            Assert.Equal(0, options.MaxRetransmits);
            Assert.Equal(1.0, options.BackoffMultiplier);
            Assert.Equal(0.0, options.JitterFraction);
            // multiplier 1.0 ⇒ every resend waits the base interval — the original fixed-rate behaviour.
            Assert.Equal(TimeSpan.FromSeconds(1), options.IntervalFor(0));
            Assert.Equal(TimeSpan.FromSeconds(1), options.IntervalFor(5));
        }

        [Fact]
        public void IntervalFor_DoublesPerResend_ThenCapsAtMax()
        {
            var options = new L2tpRetransmitOptions
            {
                Interval = TimeSpan.FromSeconds(1),
                BackoffMultiplier = 2.0,
                MaxInterval = TimeSpan.FromSeconds(8),
            };

            Assert.Equal(TimeSpan.FromSeconds(1), options.IntervalFor(0));
            Assert.Equal(TimeSpan.FromSeconds(2), options.IntervalFor(1));
            Assert.Equal(TimeSpan.FromSeconds(4), options.IntervalFor(2));
            Assert.Equal(TimeSpan.FromSeconds(8), options.IntervalFor(3));
            Assert.Equal(TimeSpan.FromSeconds(8), options.IntervalFor(4)); // 16s clamped at MaxInterval
        }
    }
}
