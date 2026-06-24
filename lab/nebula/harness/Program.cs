using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Nebula.Certificate;
using TqkLibrary.VpnClient.Nebula.Handshake;
using TqkLibrary.VpnClient.Nebula.Handshake.Models;
using TqkLibrary.VpnClient.Nebula.Packet;
using TqkLibrary.VpnClient.Nebula.Packet.Enums;
using TqkLibrary.VpnClient.Nebula.Packet.Models;

// args: <certDir> <responderIp:port>
string certDir = args[0];
string[] hp = args[1].Split(':');
var endpoint = new IPEndPoint(IPAddress.Parse(hp[0]), int.Parse(hp[1]));

var codec = new NebulaCertificateCodec();
var validator = new NebulaCertificateValidator();
var headerCodec = new NebulaHeaderCodec();
var payloadCodec = new NebulaHandshakePayloadCodec();

// Load CA, client cert + X25519 private key.
var ca = codec.UnmarshalCertificate(NebulaPem.Decode(File.ReadAllText(Path.Combine(certDir, "ca.crt"))).Body, out _);
byte[] caPub = ca.Details.PublicKey;
var clientCert = codec.UnmarshalCertificate(NebulaPem.Decode(File.ReadAllText(Path.Combine(certDir, "client.crt"))).Body, out _);
byte[] clientX25519Priv = NebulaPem.Decode(File.ReadAllText(Path.Combine(certDir, "client.key"))).Body;

// Build the cert to embed in the handshake payload: same details but with PublicKey stripped (the Noise s token
// carries the static pubkey; nebula removes field 7 from the marshaled cert in the payload).
var stripped = new TqkLibrary.VpnClient.Nebula.Certificate.Models.NebulaCertificate
{
    Details = new TqkLibrary.VpnClient.Nebula.Certificate.Models.NebulaCertificateDetails
    {
        Name = clientCert.Details.Name,
        Ips = clientCert.Details.Ips,
        Subnets = clientCert.Details.Subnets,
        Groups = clientCert.Details.Groups,
        NotBefore = clientCert.Details.NotBefore,
        NotAfter = clientCert.Details.NotAfter,
        PublicKey = Array.Empty<byte>(),      // stripped
        IsCa = clientCert.Details.IsCa,
        Issuer = clientCert.Details.Issuer,
        Curve = clientCert.Details.Curve,
    },
    Signature = clientCert.Signature,
};
byte[] strippedCertBytes = codec.MarshalCertificate(stripped);

uint initiatorIndex = (uint)Random.Shared.Next(1, int.MaxValue);
var details = new NebulaHandshakeDetails
{
    Cert = strippedCertBytes,
    InitiatorIndex = initiatorIndex,
    Time = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1_000_000UL,
};
byte[] noisePayload = payloadCodec.Marshal(details);

var hs = new NebulaNoiseIxHandshake(clientX25519Priv);
byte[] noiseMsg1 = hs.CreateInitiation(noisePayload);

var header1 = new NebulaHeader
{
    Version = 1,
    Type = NebulaMessageType.Handshake,
    SubType = (byte)NebulaMessageSubType.HandshakeIxPsk0,
    Reserved = 0,
    RemoteIndex = 0,
    MessageCounter = 1,
};
byte[] packet1 = headerCodec.EncodePacket(header1, noiseMsg1);

Console.WriteLine($"InitiatorIndex=0x{initiatorIndex:x8}  payloadLen={noisePayload.Length}  noiseMsg1Len={noiseMsg1.Length}  packet1Len={packet1.Length}");
Console.WriteLine($"Sending handshake stage1 to {endpoint} ...");

using var udp = new UdpClient(AddressFamily.InterNetwork);
udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
await udp.SendAsync(packet1, packet1.Length, endpoint);

// Wait for the response (handshake stage 2).
udp.Client.ReceiveTimeout = 6000;
var recvTask = udp.ReceiveAsync();
var completed = await Task.WhenAny(recvTask, Task.Delay(6000));
if (completed != recvTask)
{
    Console.WriteLine("TIMEOUT: no response from nebula within 6s.");
    Console.WriteLine("(Check nebula log for 'handshake message received' / 'invalid' lines.)");
    return 2;
}

UdpReceiveResult resp = recvTask.Result;
byte[] data = resp.Buffer;
Console.WriteLine($"RECEIVED {data.Length} bytes from {resp.RemoteEndPoint}");
if (!headerCodec.TryDecode(data, out NebulaHeader rh))
{
    Console.WriteLine("Response too short for a header.");
    return 3;
}
Console.WriteLine($"  resp header: ver={rh.Version} type={rh.Type} sub={rh.SubType} remoteIndex=0x{rh.RemoteIndex:x8} counter={rh.MessageCounter}");

if (rh.Type == NebulaMessageType.RecvError)
{
    Console.WriteLine("  Got RecvError — responder has no matching tunnel (handshake likely failed).");
    return 4;
}
if (rh.Type != NebulaMessageType.Handshake)
{
    Console.WriteLine($"  Unexpected type {rh.Type}; expected Handshake.");
    return 5;
}

// rh.RemoteIndex should echo our initiatorIndex; the responder's index is inside the payload.
byte[] noiseMsg2 = data.AsSpan(NebulaHeader.Size).ToArray();
if (!hs.ConsumeResponse(noiseMsg2, out byte[] respPayload))
{
    Console.WriteLine("  ConsumeResponse FAILED — could not decrypt nebula's handshake response (AEAD/transcript mismatch).");
    return 6;
}

Console.WriteLine("  *** HANDSHAKE STAGE 2 DECRYPTED OK ***");
var respDetails = payloadCodec.Unmarshal(respPayload);
Console.WriteLine($"  ResponderIndex=0x{respDetails.ResponderIndex:x8}  certLen={respDetails.Cert.Length}");

// Recombine responder cert with the static pubkey from the Noise s token and verify against the CA.
byte[]? respStaticPub = hs.RemoteStaticPublic;
if (respStaticPub is not null && respDetails.Cert.Length > 0)
{
    var respCert = codec.UnmarshalCertificate(respDetails.Cert, out _);
    respCert.Details.PublicKey = respStaticPub;               // recombine
    byte[] recombinedDetails = codec.MarshalDetails(respCert.Details);
    bool ok = validator.VerifySignature(respCert, recombinedDetails, caPub);
    Console.WriteLine($"  Responder cert name='{respCert.Details.Name}' signature-valid={ok}");
}

(byte[] send, byte[] recv) = hs.Split();
Console.WriteLine($"  Transport keys derived: send={Convert.ToHexString(send)[..16]}... recv={Convert.ToHexString(recv)[..16]}...");
Console.WriteLine("SUCCESS: real nebula accepted our Noise IX handshake and we completed it.");

// ---- STRETCH: send one encrypted data (Message) packet (an ICMP echo from 192.168.100.5 to 192.168.100.1) ----
// Data packet: header (Type=Message, RemoteIndex=responderIndex, MessageCounter=c) is the AEAD AAD;
// nonce = 4 zero bytes || counter (BIG-endian for AES-256-GCM); ciphertext = AEAD(sendKey, nonce, innerIp, aad=header).
uint responderIndex = respDetails.ResponderIndex;
ulong dataCounter = 1;
byte[] innerIp = BuildIcmpEcho(System.Net.IPAddress.Parse("192.168.100.5"), System.Net.IPAddress.Parse("192.168.100.1"));

var dataHeader = new NebulaHeader
{
    Version = 1,
    Type = NebulaMessageType.Message,
    SubType = (byte)NebulaMessageSubType.None,
    Reserved = 0,
    RemoteIndex = responderIndex,
    MessageCounter = dataCounter,
};
byte[] aad = headerCodec.Encode(dataHeader);
var gcm = new TqkLibrary.VpnClient.Crypto.Aead.AesGcmCipher(32);
byte[] nonce = new byte[12];
// big-endian counter in the last 8 bytes
for (int i = 0; i < 8; i++) nonce[11 - i] = (byte)(dataCounter >> (8 * i));
byte[] ct = new byte[innerIp.Length];
byte[] tag = new byte[16];
gcm.Seal(send, nonce, innerIp, aad, ct, tag);
byte[] dataPacket = new byte[NebulaHeader.Size + ct.Length + tag.Length];
aad.CopyTo(dataPacket.AsSpan(0));
ct.CopyTo(dataPacket.AsSpan(NebulaHeader.Size));
tag.CopyTo(dataPacket.AsSpan(NebulaHeader.Size + ct.Length));

Console.WriteLine($"\nSending one encrypted ICMP data packet ({dataPacket.Length} bytes) to {endpoint} ...");
await udp.SendAsync(dataPacket, dataPacket.Length, endpoint);
// Try to read a reply (likely none, since responder tun is disabled — we just want nebula to DECRYPT ok).
var dataRecv = udp.ReceiveAsync();
var dc = await Task.WhenAny(dataRecv, Task.Delay(3000));
if (dc == dataRecv)
{
    var r2 = dataRecv.Result;
    headerCodec.TryDecode(r2.Buffer, out NebulaHeader h2);
    Console.WriteLine($"  data reply: {r2.Buffer.Length} bytes type={h2.Type} counter={h2.MessageCounter}");
}
else
{
    Console.WriteLine("  no data reply within 3s (expected — responder tun disabled; check nebula log for decrypt result).");
}
return 0;

static byte[] BuildIcmpEcho(System.Net.IPAddress src, System.Net.IPAddress dst)
{
    // Minimal IPv4 + ICMP echo request.
    byte[] icmp = new byte[8];
    icmp[0] = 8; // echo request
    icmp[1] = 0;
    icmp[4] = 0x12; icmp[5] = 0x34; // id
    icmp[6] = 0x00; icmp[7] = 0x01; // seq
    ushort icmpCk = Checksum(icmp);
    icmp[2] = (byte)(icmpCk >> 8); icmp[3] = (byte)icmpCk;

    byte[] ip = new byte[20 + icmp.Length];
    ip[0] = 0x45; // v4, ihl 5
    int total = ip.Length;
    ip[2] = (byte)(total >> 8); ip[3] = (byte)total;
    ip[8] = 64;   // ttl
    ip[9] = 1;    // icmp
    src.GetAddressBytes().CopyTo(ip, 12);
    dst.GetAddressBytes().CopyTo(ip, 16);
    ushort ipCk = Checksum(ip.AsSpan(0, 20));
    ip[10] = (byte)(ipCk >> 8); ip[11] = (byte)ipCk;
    icmp.CopyTo(ip, 20);
    return ip;
}

static ushort Checksum(ReadOnlySpan<byte> data)
{
    uint sum = 0;
    for (int i = 0; i + 1 < data.Length; i += 2) sum += (uint)((data[i] << 8) | data[i + 1]);
    if ((data.Length & 1) == 1) sum += (uint)(data[^1] << 8);
    while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return (ushort)~sum;
}
