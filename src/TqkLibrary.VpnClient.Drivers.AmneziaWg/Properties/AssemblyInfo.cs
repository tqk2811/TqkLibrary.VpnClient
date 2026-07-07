using System.Runtime.CompilerServices;

// Expose internals to the offline test assembly (parity with the other driver projects); currently all obfuscation
// types are public, but this keeps the door open for internal helpers without touching the test project.
[assembly: InternalsVisibleTo("TqkLibrary.VpnClient.Drivers.AmneziaWg.Tests")]
