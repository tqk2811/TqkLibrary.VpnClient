using System.Runtime.CompilerServices;

// The EoGRE data-plane channel is internal (it is wired only inside EoGreConnection); expose it to the test assembly so
// the offline unit tests can drive EoGreEthernetChannel directly (mirroring how the Geneve driver's channel is unit-tested).
[assembly: InternalsVisibleTo("TqkLibrary.VpnClient.Drivers.EoGre.Tests")]
