namespace TqkLibrary.Vpn.Ppp.Enums
{
    /// <summary>Result of feeding an authentication packet to an <see cref="Interfaces.IPppAuthenticator"/>.</summary>
    public enum PppAuthStatus
    {
        /// <summary>Authentication is still in progress (a response may have been produced).</summary>
        Pending = 0,

        /// <summary>The peer authenticated us successfully.</summary>
        Success = 1,

        /// <summary>Authentication failed.</summary>
        Failure = 2,
    }
}
