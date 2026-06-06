using System.Net;
using System.Security.Cryptography;

namespace TqkLibrary.Vpn.Ipsec.Ike
{
    /// <summary>
    /// NAT-detection hashes for IKE_SA_INIT (RFC 7296 §2.23): <c>SHA1(SPIi | SPIr | IP | Port)</c>.
    /// A peer concludes there is NAT on a path when the hash it receives does not match the one it computes
    /// over its own view of the address — which is exactly what makes a userspace ephemeral source port
    /// look "NATed" and pushes the server onto UDP/4500.
    /// </summary>
    public static class NatDetection
    {
        /// <summary>Computes the 20-byte NAT-detection hash over the SPIs and the given IP endpoint.</summary>
        public static byte[] ComputeHash(byte[] initiatorSpi, byte[] responderSpi, IPAddress ip, ushort port)
        {
            byte[] address = ip.GetAddressBytes();
            byte[] data = new byte[initiatorSpi.Length + responderSpi.Length + address.Length + 2];
            int offset = 0;
            Buffer.BlockCopy(initiatorSpi, 0, data, offset, initiatorSpi.Length); offset += initiatorSpi.Length;
            Buffer.BlockCopy(responderSpi, 0, data, offset, responderSpi.Length); offset += responderSpi.Length;
            Buffer.BlockCopy(address, 0, data, offset, address.Length); offset += address.Length;
            data[offset] = (byte)(port >> 8);
            data[offset + 1] = (byte)port;

            using var sha1 = SHA1.Create();
            return sha1.ComputeHash(data);
        }
    }
}
