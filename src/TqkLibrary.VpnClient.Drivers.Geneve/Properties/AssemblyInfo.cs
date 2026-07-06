using System.Runtime.CompilerServices;

// The Geneve data-plane channel is internal (it is wired only inside GeneveConnection); expose it to the test assembly so
// the offline unit tests can drive GeneveEthernetChannel directly (mirroring how the VXLAN driver's channel is unit-tested).
[assembly: InternalsVisibleTo("TqkLibrary.VpnClient.Drivers.Geneve.Tests")]
