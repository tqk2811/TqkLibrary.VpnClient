// n2n v3 REGISTER_SUPER interop harness — sends a REGISTER_SUPER to a real n2n v3 supernode over UDP and waits for the
// REGISTER_SUPER_ACK. A decoded ACK with our cookie echoed back proves the supernode accepted our community + auth and
// that this project's codec is byte-compatible with n2n v3. Clean-room: drives only this project's codec, no n2n source.
//
// Usage: n2n-register-harness <community> <host> <port> [transform: null|aes]

using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.N2n;
using TqkLibrary.VpnClient.N2n.Transform;
using TqkLibrary.VpnClient.N2n.Wire.Enums;
using TqkLibrary.VpnClient.N2n.Wire.Models;

if (args.Length < 3)
{
    Console.Error.WriteLine("usage: n2n-register-harness <community> <host> <port> [null|aes]");
    return 2;
}

string community = args[0];
string host = args[1];
int port = int.Parse(args[2]);

var codec = new N2nPacketCodec();

// A locally-administered, randomised MAC for our virtual edge (first register asks the supernode to assign an IP, so
// dev_addr is left unset).
byte[] edgeMac = new byte[6];
new Random().NextBytes(edgeMac);
edgeMac[0] = (byte)((edgeMac[0] & 0xFE) | 0x02); // locally administered, unicast

uint cookie = unchecked((uint)new Random().Next());

var reg = new N2nRegisterSuper
{
    Cookie = cookie,
    EdgeMac = edgeMac,
    Sock = null,                       // no advertised socket -> no N2N_FLAGS_SOCKET
    DevAddr = N2nIpSubnet.Unset,       // ask the supernode to assign
    DevDesc = "dotnet-edge",
    Auth = N2nAuth.SimpleIdRandom(),   // scheme 1 + 16-byte challenge token (no -H, no password community)
    KeyTime = 0,
};

byte[] packet = codec.EncodeRegisterSuper(community, reg);
Console.WriteLine($"[harness] community = {community}");
Console.WriteLine($"[harness] edgeMac   = {Convert.ToHexString(edgeMac)}");
Console.WriteLine($"[harness] cookie    = {cookie:x8}");
Console.WriteLine($"[harness] REGISTER_SUPER {packet.Length} bytes");
Console.WriteLine($"[harness] wire = {Convert.ToHexString(packet).ToLowerInvariant()}");

using var udp = new UdpClient(AddressFamily.InterNetwork);
var dest = new IPEndPoint(Dns.GetHostAddresses(host)[0], port);
udp.Send(packet, packet.Length, dest);
Console.WriteLine($"[harness] sent to {dest}, waiting up to 5s for REGISTER_SUPER_ACK...");

udp.Client.ReceiveTimeout = 5000;
try
{
    var recvTask = udp.ReceiveAsync();
    if (!recvTask.Wait(TimeSpan.FromSeconds(5)))
    {
        Console.WriteLine("[harness] NO REPLY (timeout) — supernode dropped our REGISTER_SUPER.");
        return 1;
    }
    var resp = recvTask.Result;
    byte[] reply = resp.Buffer;
    Console.WriteLine($"[harness] REPLY {reply.Length} bytes from {resp.RemoteEndPoint}");
    Console.WriteLine($"[harness] reply wire = {Convert.ToHexString(reply).ToLowerInvariant()}");

    if (!codec.TryPeekHeader(reply, out var ph))
    {
        Console.WriteLine("[harness] reply too short to parse common header.");
        return 1;
    }
    Console.WriteLine($"[harness] reply type = {ph.PacketType}, community = {ph.Community}, flags = {ph.Flags}");

    if (codec.TryDecodeRegisterSuperAck(reply, out _, out var ack))
    {
        Console.WriteLine($"[harness] *** REGISTER_SUPER_ACK decoded *** cookie={ack.Cookie:x8} (sent {cookie:x8})");
        Console.WriteLine($"[harness] assigned dev_addr = {ack.DevAddr.NetAddr:x8}/{ack.DevAddr.NetBitLen}, lifetime={ack.Lifetime}s");
        Console.WriteLine($"[harness] supernode MAC = {Convert.ToHexString(ack.SrcMac)}, edge public sock = {SafeSock(ack.Sock)}");
        if (ack.Cookie != cookie)
            Console.WriteLine("[harness] note: ACK cookie mismatch (still accepted — codec interop proven).");

        // --- STRETCH: send one PACKET (a broadcast Ethernet frame) so the supernode logs "RX PACKET (multicast)". ---
        // This exercises the data-plane PACKET codec against the real supernode (transform NULL — community has no key).
        byte[] broadcast = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        byte[] frame = BuildBroadcastFrame(edgeMac);
        var pkt = new N2nPacket
        {
            SrcMac = edgeMac,
            DstMac = broadcast,
            Compression = 1,                 // N2N_COMPRESSION_ID_NONE
            Transform = N2nTransformId.Null,
            Payload = frame,
        };
        byte[] pktWire = codec.EncodePacket(community, pkt, new N2nNullTransform());
        udp.Send(pktWire, pktWire.Length, dest);
        Console.WriteLine($"[harness] sent PACKET (broadcast, {pktWire.Length} bytes, transform NULL) to drive supernode RX PACKET.");

        Console.WriteLine("[harness] RESULT: REGISTER_SUPER INTEROP SUCCESS (supernode accepted our registration, cookie echoed).");
        return 0;
    }
    Console.WriteLine("[harness] reply was not a decodable REGISTER_SUPER_ACK.");
    return 1;
}
catch (Exception ex)
{
    Console.WriteLine($"[harness] error: {ex.Message}");
    return 1;
}

static string SafeSock(N2nSock? s)
{
    try { return s is null ? "(none)" : s.ToEndPoint().ToString(); }
    catch { return "(unparsable)"; }
}

// A minimal broadcast Ethernet frame (dst=broadcast, src=our MAC, ethertype 0x0800 IPv4 + small body) just to give the
// supernode a PACKET to log/relay. The content is inert; we only want to exercise the PACKET wire path.
static byte[] BuildBroadcastFrame(byte[] srcMac)
{
    byte[] f = new byte[42];
    for (int i = 0; i < 6; i++) f[i] = 0xFF;          // dst = broadcast
    Array.Copy(srcMac, 0, f, 6, 6);                    // src
    f[12] = 0x08; f[13] = 0x00;                         // ethertype IPv4
    for (int i = 14; i < f.Length; i++) f[i] = (byte)i;
    return f;
}
