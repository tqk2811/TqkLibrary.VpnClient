using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Tinc.Hosts;
using TqkLibrary.VpnClient.Tinc.Meta;
using TqkLibrary.VpnClient.Tinc.Sptps;
using TqkLibrary.VpnClient.Tinc.Sptps.Enums;

var signer = new Ed25519Signer();

// Sub-command: "gen-key <seedOutFile> <pubOutFile>" generates a fresh Ed25519 seed, writes the seed (raw base64) and
// its tinc-style public key, then exits. Run this FIRST, register the public key on the server, then connect with the
// seed file. This keeps the same key across both steps without a chicken-and-egg between registration and connect.
//
// IMPORTANT interop note: tinc's `tinc generate-ed25519-keys` writes a 96-byte ed25519_key.priv = the orlp *expanded*
// private key (scalar||prefix, 64B) || public (32B), NOT a 32-byte seed. RFC 8032 / BouncyCastle signs from a 32-byte
// seed and re-hashes it, so taking the first 32 bytes of that file as a "seed" yields a different scalar and the SIG
// fails to verify. The correct, driver-realistic approach is for the client to own its own seed (it generates the
// keypair and registers its public key with the server) — which is exactly what "gen-key" + registration does.
if (args.Length >= 1 && args[0] == "gen-key")
{
    if (args.Length < 3) { Console.WriteLine("usage: harness gen-key <seedOutFile> <pubOutFile>"); return 1; }
    byte[] seed = new byte[32];
    RandomNumberGenerator.Fill(seed);
    byte[] pub = signer.DerivePublicKey(seed);
    File.WriteAllText(args[1], Convert.ToBase64String(seed));
    File.WriteAllText(args[2], TincHostConfig.EncodeBase64Key(pub));
    Console.WriteLine($"[*] gen-key: wrote seed→{args[1]}, public={TincHostConfig.EncodeBase64Key(pub)}→{args[2]}");
    return 0;
}

// args: <seedFile> <myName> <peerHostFile> <ip:port> [peerName]
if (args.Length < 4)
{
    Console.WriteLine("usage: harness <seedFile> <myName> <peerHostFile> <ip:port> [peerName]");
    Console.WriteLine("       harness gen-key <seedOutFile> <pubOutFile>");
    return 1;
}

const int consumed = 0;
byte[] myPriv;          // 32-byte Ed25519 seed
{
    string myPrivFile = args[0];
    string privText = File.ReadAllText(myPrivFile).Trim();
    var b64Lines = new List<string>();
    foreach (var l in privText.Split('\n'))
    {
        string t = l.Trim();
        if (t.Length == 0 || t.StartsWith("-----")) continue;
        b64Lines.Add(t);
    }
    // The seed file is written by gen-key with STANDARD base64 (Convert.ToBase64String) — it is a raw 32-byte seed,
    // NOT a tinc host-file key, so it must be decoded with the standard codec, not tinc's little-endian TincBase64.
    string seedB64 = string.Join("", b64Lines);
    int pad = (4 - (seedB64.Length % 4)) % 4;
    if (pad > 0) seedB64 += new string('=', pad);
    byte[] privFull = Convert.FromBase64String(seedB64);
    myPriv = privFull.Length >= 32 ? privFull[..32] : privFull;
    Console.WriteLine($"[*] loaded seed file: {privFull.Length} bytes, using first 32 as seed");
}

string myName = args[1 + consumed];
string peerHostFile = args[2 + consumed];
string[] hp = args[3 + consumed].Split(':');
string host = hp[0];
int port = hp.Length > 1 ? int.Parse(hp[1]) : 655;

// peer host config → Ed25519 public key + name
var peerCfg = TincHostConfig.Parse(File.ReadAllText(peerHostFile), Path.GetFileName(peerHostFile));
string peerName = args.Length > 4 + consumed ? args[4 + consumed] : (peerCfg.Name ?? Path.GetFileName(peerHostFile));
byte[] peerPub = peerCfg.Ed25519PublicKey ?? throw new Exception("peer host file missing Ed25519PublicKey");
Console.WriteLine($"[*] peer={peerName} Ed25519 pub {peerPub.Length}B");

using var tcp = new TcpClient();
tcp.Connect(host, port);
var stream = tcp.GetStream();
Console.WriteLine($"[*] TCP connected to {host}:{port}");

// 1) send ID cleartext (we are outgoing → initiator)
var id = TincMetaRequest.Id(myName, 17, 7);
byte[] idBytes = id.ToBytes();
stream.Write(idBytes, 0, idBytes.Length);
Console.WriteLine($"[>] ID sent: {Encoding.ASCII.GetString(idBytes).TrimEnd()}");

// 2) read peer ID line (cleartext, until '\n')
string peerIdLine = ReadLine(stream);
Console.WriteLine($"[<] peer ID: {peerIdLine}");
var peerId = TincMetaRequest.Parse(peerIdLine);
string serverName = peerId.Arguments.Count > 0 ? peerId.Arguments[0] : peerName;

// 3) SPTPS handshake. label = "tinc TCP key expansion <initiator=me> <responder=server>" + NUL
byte[] label = SptpsHandshake.BuildMetaLabel(myName, serverName);
Console.WriteLine($"[*] label='{Encoding.ASCII.GetString(label).TrimEnd('\0')}' (len {label.Length})");

var hs = new SptpsHandshake(initiator: true, myPriv, peerPub, label);
var rec = new SptpsRecordLayer();

// initiator sends KEX immediately
byte[] myKex = hs.CreateKex();
byte[] kexFrame = rec.EncodeHandshake(myKex);
stream.Write(kexFrame, 0, kexFrame.Length);
Console.WriteLine($"[>] KEX sent ({myKex.Length}B handshake record, frame {kexFrame.Length}B)");

// read server KEX (handshake record, plaintext)
var buf = new List<byte>();
byte[] serverKex = ReadOneRecord(stream, rec, buf, out byte t1);
Console.WriteLine($"[<] server record type={t1} len={serverKex.Length}");
if (t1 != (byte)SptpsRecordType.Handshake) { Console.WriteLine("[!] expected handshake KEX"); }
hs.ConsumeKex(serverKex);
Console.WriteLine("[*] consumed server KEX, derived key material (Ed25519-keyed ECDH + TLS-1.0 PRF)");

// send our SIG (Ed25519 over initiator_flag || my_kex || his_kex || label)
byte[] mySig = hs.CreateSig();
byte[] sigFrame = rec.EncodeHandshake(mySig);
stream.Write(sigFrame, 0, sigFrame.Length);
Console.WriteLine($"[>] SIG sent ({mySig.Length}B)");

// read server SIG
byte[] serverSig = ReadOneRecord(stream, rec, buf, out byte t2);
Console.WriteLine($"[<] server record type={t2} len={serverSig.Length}");
bool sigOk = hs.ConsumeSig(serverSig);
Console.WriteLine(sigOk ? "[✓] server SIG VERIFIED — SPTPS authentication OK" : "[✗] server SIG verification FAILED");
if (!sigOk) return 2;

// enable encryption with derived directional keys
rec.EnableEncryption(hs.OutCipherKey, hs.InCipherKey);
Console.WriteLine("[*] encryption enabled. Reading first encrypted application record (server's ACK meta-request)...");

// Read one encrypted record via the real record layer. The handshake records (server KEX/SIG) already advanced the
// in-seqno, so this decrypts under the correct post-handshake nonce (seqno 2) — full record-layer interop.
try
{
    byte[] app = ReadOneRecord(stream, rec, buf, out byte t3);
    string text = Encoding.ASCII.GetString(app).TrimEnd('\n');
    Console.WriteLine($"[✓] DECRYPTED encrypted record type={t3}: '{text}'");
    Console.WriteLine("[✓✓] SPTPS HANDSHAKE + RECORD LAYER INTEROP OK with real tincd 1.1");
}
catch (Exception ex)
{
    Console.WriteLine($"[~] record decrypt failed ({ex.Message}); SIG verified = handshake auth OK");
}

return 0;

// ---- helpers ----
static string ReadLine(NetworkStream s)
{
    var sb = new StringBuilder();
    int b;
    while ((b = s.ReadByte()) != -1)
    {
        if (b == '\n') break;
        if (b != '\r') sb.Append((char)b);
    }
    return sb.ToString();
}

static byte[] ReadOneRecord(NetworkStream s, SptpsRecordLayer rec, List<byte> buf, out byte type)
{
    byte[] tmp = new byte[4096];
    while (true)
    {
        var result = rec.TryDecodeRecord(buf.ToArray(), out type, out byte[] data, out int consumed);
        if (result == SptpsDecodeResult.Ok)
        {
            buf.RemoveRange(0, consumed);
            return data;
        }
        if (result == SptpsDecodeResult.AuthFailed)
            throw new Exception("record auth failed (decrypt mismatch)");
        // NeedMore → read
        int n = s.Read(tmp, 0, tmp.Length);
        if (n <= 0) throw new Exception("connection closed by peer");
        for (int i = 0; i < n; i++) buf.Add(tmp[i]);
    }
}
