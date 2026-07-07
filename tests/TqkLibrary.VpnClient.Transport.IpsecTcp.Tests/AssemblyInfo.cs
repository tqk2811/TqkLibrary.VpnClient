using Xunit;

// The loopback end-to-end tests bounce datagrams through in-memory byte-stream pipes on thread-pool continuations.
// Serialise this assembly's classes to keep those in-process exchanges deterministic (a test-harness constraint only;
// real transports are async sockets).
[assembly: CollectionBehavior(DisableTestParallelization = true)]
