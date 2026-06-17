using Xunit;

// The end-to-end tests each drive a full OpenConnect connect against an in-process ocserv responder; auth, CONNECT and
// CSTP frames bounce through a loopback byte stream on thread-pool continuations. Run in parallel across classes on a
// low-core box, those can starve the thread pool. Real transports are async TLS sockets, so this is a test-harness
// constraint only — serialise this assembly's classes to keep the in-process exchanges deterministic.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
