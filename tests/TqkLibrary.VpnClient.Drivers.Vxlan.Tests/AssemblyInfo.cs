using Xunit;

// The end-to-end tests each drive a full VXLAN connect against an in-process peer; data bounces several datagrams through
// the loopback's thread-pool continuations. Serialise this assembly's classes to keep the in-process exchanges
// deterministic (a test-harness constraint only — real transports are async sockets).
[assembly: CollectionBehavior(DisableTestParallelization = true)]
