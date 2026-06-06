namespace TqkLibrary.Vpn.Ipsec.Ike.Enums
{
    /// <summary>Transform types inside an IKEv2 proposal (RFC 7296 §3.3.2).</summary>
    public enum IkeTransformType : byte
    {
        /// <summary>Encryption algorithm (ENCR).</summary>
        Encryption = 1,

        /// <summary>Pseudo-random function (PRF).</summary>
        Prf = 2,

        /// <summary>Integrity algorithm (INTEG).</summary>
        Integrity = 3,

        /// <summary>Diffie-Hellman group (D-H).</summary>
        DiffieHellman = 4,

        /// <summary>Extended Sequence Numbers (ESN).</summary>
        ExtendedSequenceNumbers = 5,
    }
}
