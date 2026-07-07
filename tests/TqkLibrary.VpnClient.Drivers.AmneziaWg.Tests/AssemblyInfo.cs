using Xunit;

// The decorator/factory tests drive in-process datagram pipes whose delivery bounces through thread-pool continuations.
// Serialise this assembly's classes to keep those in-memory exchanges deterministic (a test-harness constraint only).
[assembly: CollectionBehavior(DisableTestParallelization = true)]
