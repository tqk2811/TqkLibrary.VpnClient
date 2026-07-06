using System.Runtime.CompilerServices;

// The VXLAN-GPE data-plane channel is internal (it is wired only inside VxlanGpeConnection); expose it to the test assembly
// so the offline unit tests can drive VxlanGpeEthernetChannel directly (mirroring how the VXLAN driver's channel is unit-tested).
[assembly: InternalsVisibleTo("TqkLibrary.VpnClient.Drivers.VxlanGpe.Tests")]
