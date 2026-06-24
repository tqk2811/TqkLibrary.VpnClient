namespace TqkLibrary.VpnClient.Drivers.Nebula.Enums
{
    /// <summary>The lifecycle state of a <see cref="NebulaConnection"/> (mirrors the other drivers' state enums).</summary>
    public enum NebulaConnectionState
    {
        /// <summary>No tunnel (initial / after teardown).</summary>
        Disconnected,

        /// <summary>Running the initial Noise IX handshake.</summary>
        Connecting,

        /// <summary>Tunnel up and carrying traffic.</summary>
        Connected,

        /// <summary>The tunnel dropped and the supervisor is re-establishing it.</summary>
        Reconnecting,
    }
}
