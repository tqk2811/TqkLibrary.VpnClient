using System.Runtime.CompilerServices;

// Expose internals to the offline test assembly: BouncyCastleDatagramBridge is internal and its non-blocking Send is
// unit-tested directly.
[assembly: InternalsVisibleTo("TqkLibrary.VpnClient.Transport.Dtls.Tests")]
