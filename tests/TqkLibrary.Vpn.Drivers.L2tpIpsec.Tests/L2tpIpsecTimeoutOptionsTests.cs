using TqkLibrary.Vpn.L2tp;
using Xunit;

namespace TqkLibrary.Vpn.Drivers.L2tpIpsec.Tests
{
    public class L2tpIpsecTimeoutOptionsTests
    {
        [Fact]
        public void Defaults_RetransmitWithBackoffAndJitter()
        {
            var options = new L2tpIpsecTimeoutOptions();

            Assert.Equal(TimeSpan.FromSeconds(2.5), options.IkeRetransmitInterval);
            Assert.Equal(2.0, options.IkeBackoffMultiplier);
            Assert.Equal(TimeSpan.FromSeconds(20), options.IkeMaxRetransmitInterval);
            Assert.Equal(5, options.IkeMaxAttempts);
            Assert.Equal(TimeSpan.FromSeconds(1), options.L2tpRetransmitInterval);
            Assert.Equal(2.0, options.L2tpBackoffMultiplier);
            Assert.Equal(TimeSpan.FromSeconds(8), options.L2tpMaxRetransmitInterval);
            Assert.Equal(8, options.L2tpMaxRetransmits);
            Assert.Equal(0.2, options.RetransmitJitterFraction);
        }

        [Fact]
        public void IkeIntervalFor_DoublesPerAttempt_ThenCapsAtMax()
        {
            var options = new L2tpIpsecTimeoutOptions
            {
                IkeRetransmitInterval = TimeSpan.FromSeconds(2.5),
                IkeBackoffMultiplier = 2.0,
                IkeMaxRetransmitInterval = TimeSpan.FromSeconds(20),
            };

            Assert.Equal(TimeSpan.FromSeconds(2.5), options.IkeIntervalFor(0));
            Assert.Equal(TimeSpan.FromSeconds(5), options.IkeIntervalFor(1));
            Assert.Equal(TimeSpan.FromSeconds(10), options.IkeIntervalFor(2));
            Assert.Equal(TimeSpan.FromSeconds(20), options.IkeIntervalFor(3));
            Assert.Equal(TimeSpan.FromSeconds(20), options.IkeIntervalFor(4)); // 40s clamped at IkeMaxRetransmitInterval
        }

        [Fact]
        public void IkeIntervalFor_Multiplier1_IsFixed()
        {
            var options = new L2tpIpsecTimeoutOptions { IkeRetransmitInterval = TimeSpan.FromSeconds(3), IkeBackoffMultiplier = 1.0 };

            Assert.Equal(TimeSpan.FromSeconds(3), options.IkeIntervalFor(0));
            Assert.Equal(TimeSpan.FromSeconds(3), options.IkeIntervalFor(5));
        }

        [Fact]
        public void BuildL2tpRetransmitOptions_MapsEveryField()
        {
            var options = new L2tpIpsecTimeoutOptions
            {
                L2tpRetransmitInterval = TimeSpan.FromSeconds(1),
                L2tpMaxRetransmits = 8,
                L2tpBackoffMultiplier = 2.0,
                L2tpMaxRetransmitInterval = TimeSpan.FromSeconds(8),
                RetransmitJitterFraction = 0.2,
            };

            L2tpRetransmitOptions mapped = options.BuildL2tpRetransmitOptions();

            Assert.Equal(TimeSpan.FromSeconds(1), mapped.Interval);
            Assert.Equal(8, mapped.MaxRetransmits);
            Assert.Equal(2.0, mapped.BackoffMultiplier);
            Assert.Equal(TimeSpan.FromSeconds(8), mapped.MaxInterval);
            Assert.Equal(0.2, mapped.JitterFraction);
        }
    }
}
