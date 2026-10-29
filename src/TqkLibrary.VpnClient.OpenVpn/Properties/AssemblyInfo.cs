using System.Runtime.CompilerServices;

// Expose internals to the offline test assembly: the TLS bridge stream (OpenVpnTlsBridgeStream) is internal and its
// sync/async read-write contract is unit-tested directly.
[assembly: InternalsVisibleTo("TqkLibrary.VpnClient.OpenVpn.Tests")]
