using System.Security.Cryptography.X509Certificates;
using TqkLibrary.Vpn.Abstractions.Transport.Interfaces;

namespace TqkLibrary.Vpn.Drivers.Sstp.Transport
{
    /// <summary>
    /// A TLS byte-stream transport (<see cref="IByteStreamTransport"/>) that also exposes the server's certificate.
    /// SSTP's crypto binding ([MS-SSTP] §3.2.4) hashes this certificate, so the framing layer needs access to it; the
    /// accessor is kept off the generic <see cref="IByteStreamTransport"/> (which stays Connect/Read/Write only) and
    /// lives on this thin extension. That keeps the byte-pipe contract reusable (roadmap F.1) while letting a fake
    /// stream supply a stub certificate so the SSTP handshake/supervisor can be exercised offline.
    /// </summary>
    public interface ITlsByteStream : IByteStreamTransport
    {
        /// <summary>The server's TLS certificate, captured during the handshake (<c>null</c> until connected).</summary>
        X509Certificate2? RemoteCertificate { get; }
    }
}
