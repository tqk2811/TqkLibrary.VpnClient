namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// Exports keying material from an established TLS session per <b>RFC 5705</b> (the TLS keying-material exporter).
    /// OpenVPN's <c>--key-derivation tls-ekm</c> mode (IV_PROTO bit <see cref="DataChannel.OpenVpnPeerInfo.IvProtoTlsKeyExport"/>)
    /// derives the data-channel keys straight from this exporter — over label <c>"EXPORTER-OpenVPN-datakeys"</c> — instead of
    /// the classic key-method-2 PRF blend of the exchanged <c>key_source2</c> randoms
    /// (see <see cref="DataChannel.OpenVpnKeyMethod2.DeriveKey2"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Realized (roadmap F.5).</b> The default TLS engine on the control channel is
    /// <see cref="System.Net.Security.SslStream"/>, which <b>does not</b> expose an RFC 5705 exporter on
    /// <c>netstandard2.0</c> or <c>net8.0</c> (<c>SslStream.ExportKeyingMaterial(...)</c> was only added in <b>.NET 9</b>),
    /// so the implementation routes the control-channel TLS through <b>BouncyCastle TLS</b>
    /// (<see cref="OpenVpnBouncyCastleControlTls"/>, which wraps <c>Org.BouncyCastle.Tls.TlsClientProtocol</c> over the
    /// in-memory <see cref="OpenVpnTlsBridgeStream"/> and runs <c>TlsContext.ExportKeyingMaterial</c>).
    /// </para>
    /// <para>
    /// This is opt-in: the control channel selects the BouncyCastle engine only when <c>key-derivation tls-ekm</c> is
    /// requested. Without it the client keeps the live-validated key-method-2 PRF path over <see cref="SslStream"/>.
    /// </para>
    /// </remarks>
    public interface ITlsKeyingMaterialExporter
    {
        /// <summary>
        /// Returns <paramref name="length"/> bytes of exporter output (RFC 5705) for <paramref name="label"/> with an
        /// optional <paramref name="context"/> (OpenVPN <c>tls-ekm</c> uses an empty context). Implementations bind to the
        /// finished TLS session; calling before the handshake completes is invalid.
        /// </summary>
        byte[] Export(string label, ReadOnlySpan<byte> context, int length);
    }
}
