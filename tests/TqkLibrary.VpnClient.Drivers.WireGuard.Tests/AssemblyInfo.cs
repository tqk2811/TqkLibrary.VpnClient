using Xunit;

// The end-to-end tests each drive a full WireGuard connect against an in-process responder; data and rekey bounce
// several datagrams through the loopback's thread-pool continuations. Run in parallel across classes on a low-core box,
// those can starve the thread pool. Real transports are async sockets, so this is a test-harness constraint only —
// serialise this assembly's classes to keep the in-process exchanges deterministic.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
