using System.Runtime.CompilerServices;

// The L2TPv3 data-plane channel is internal (it is wired only inside L2tpv3EthConnection); expose it to the test assembly so
// the offline unit tests can drive L2tpv3EthEthernetChannel directly (mirroring how the Geneve driver's channel is unit-tested).
[assembly: InternalsVisibleTo("TqkLibrary.VpnClient.Drivers.L2tpv3Eth.Tests")]
