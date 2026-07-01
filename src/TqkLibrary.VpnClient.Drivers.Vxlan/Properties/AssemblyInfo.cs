using System.Runtime.CompilerServices;

// The VXLAN data-plane channel is internal (it is wired only inside VxlanConnection); expose it to the test assembly so
// the offline unit tests can drive VxlanEthernetChannel directly (mirroring how n2n's public channel is unit-tested).
[assembly: InternalsVisibleTo("TqkLibrary.VpnClient.Drivers.Vxlan.Tests")]
