using System.Globalization;
using System.Net;
using TqkLibrary.VpnClient.Drivers.Tailscale;
using TqkLibrary.VpnClient.Drivers.Tailscale.Config;
using TqkLibrary.VpnClient.IpStack;

// args: <config.tailscale> [pingTargetOverlayIp] [holdSeconds]
//   config: ini (server=, authkey=, mtu=, endpoint=<ip:port>, wgport=, machinekey=<64hex>, nodekey=<64hex>)
//   pingTargetOverlayIp: a peer's 100.64.x overlay IP to ICMP-ping (omit to just hold the tunnel up as responder)
//   holdSeconds: how long to keep the tunnel up / how long to keep pinging (default 60)
if (args.Length < 1)
{
    Console.Error.WriteLine("usage: harness <config.tailscale> [pingTargetOverlayIp] [holdSeconds]");
    return 2;
}

string configPath = args[0];
IPAddress? pingTarget = args.Length >= 2 && !string.IsNullOrWhiteSpace(args[1]) ? IPAddress.Parse(args[1]) : null;
int holdSeconds = args.Length >= 3 && int.TryParse(args[2], out int h) ? h : 60;

TailscaleConfig config = ParseTailscale(File.ReadAllText(configPath));
Console.WriteLine($"[harness] control login to {config.ServerUrl} (ts2021 Noise IK + preauth) ...");

var vpn = new TailscaleConnection(config);
try
{
    using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(90));
    await vpn.ConnectAsync(connectCts.Token);

    IPAddress overlay = vpn.Config.AssignedAddress ?? IPAddress.Any;
    Console.WriteLine($"[harness] TUNNEL UP. my overlay IP = {overlay}, mtu = {vpn.PacketChannel.Mtu}");

    var stack = new TcpIpStack(vpn.PacketChannel, overlay); // answers inbound ICMP echo automatically (responder side)

    if (pingTarget is null)
    {
        Console.WriteLine($"[harness] no ping target — holding the tunnel up for {holdSeconds}s (will answer inbound ICMP).");
        await Task.Delay(TimeSpan.FromSeconds(holdSeconds));
        Console.WriteLine("[harness] hold elapsed; tearing down.");
    }
    else
    {
        Console.WriteLine($"[harness] pinging peer overlay {pingTarget} over the WireGuard tunnel ...");
        int ok = 0, sent = 0;
        var deadline = DateTime.UtcNow.AddSeconds(holdSeconds);
        for (int seq = 1; DateTime.UtcNow < deadline; seq++)
        {
            sent++;
            try
            {
                using var pingCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                PingReply reply = await stack.PingAsync(pingTarget, cancellationToken: pingCts.Token);
                ok++;
                Console.WriteLine($"[harness] reply from {pingTarget}: seq={seq} rtt={reply.RoundTripTime.TotalMilliseconds:F0}ms");
            }
            catch (OperationCanceledException) { Console.WriteLine($"[harness] seq={seq} timeout (no reply)"); }
            catch (Exception ex) { Console.WriteLine($"[harness] seq={seq} error: {ex.GetType().Name}: {ex.Message}"); }
            await Task.Delay(1000);
        }
        Console.WriteLine($"[harness] PING SUMMARY: {ok}/{sent} replies from {pingTarget}");
        if (ok == 0) { await vpn.DisposeAsync(); return 1; }
    }

    await vpn.DisposeAsync();
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[harness] FAILED: {ex.GetType().Name}: {ex.Message}");
    try { await vpn.DisposeAsync(); } catch { }
    return 1;
}

static TailscaleConfig ParseTailscale(string text)
{
    string? server = null, authkey = null, hostname = null, endpoint = null, machineHex = null, nodeHex = null;
    int mtu = 1280, wgport = 0;
    foreach (string raw in text.Split('\n'))
    {
        string line = raw.Trim();
        if (line.Length == 0 || line.StartsWith("#") || line.StartsWith(";")) continue;
        int eq = line.IndexOf('=');
        if (eq <= 0) continue;
        string key = line.Substring(0, eq).Trim().ToLowerInvariant();
        string val = line.Substring(eq + 1).Trim();
        switch (key)
        {
            case "server": case "serverurl": case "url": server = val; break;
            case "authkey": case "preauthkey": case "key": authkey = val; break;
            case "hostname": hostname = val; break;
            case "mtu": int.TryParse(val, out mtu); break;
            case "wgport": case "wireguardport": int.TryParse(val, out wgport); break;
            case "endpoint": case "advertise": endpoint = val; break;
            case "machinekey": machineHex = val; break;
            case "nodekey": nodeHex = val; break;
        }
    }
    if (string.IsNullOrEmpty(server)) throw new InvalidOperationException(".tailscale needs server=<headscale base url>.");
    if (string.IsNullOrEmpty(authkey)) throw new InvalidOperationException(".tailscale needs authkey=<preauth key>.");
    byte[] machineKey = machineHex is not null ? Hex32(machineHex) : NewKey();
    byte[] nodeKey = nodeHex is not null ? Hex32(nodeHex) : NewKey();
    string[] endpoints = string.IsNullOrEmpty(endpoint) ? Array.Empty<string>() : new[] { endpoint! };
    return new TailscaleConfig
    {
        ServerUrl = new Uri(server!),
        PreauthKey = authkey!,
        MachinePrivateKey = machineKey,
        NodePrivateKey = nodeKey,
        Hostname = hostname,
        Mtu = mtu <= 0 ? 1280 : mtu,
        WireGuardLocalPort = wgport,
        AdvertisedEndpoints = endpoints,
    };
}

static byte[] NewKey()
{
    byte[] k = new byte[32];
    using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
    rng.GetBytes(k);
    return k;
}

static byte[] Hex32(string hex)
{
    hex = hex.Trim();
    if (hex.Length != 64) throw new FormatException("key must be 64 hex chars (32 bytes).");
    byte[] b = new byte[32];
    for (int i = 0; i < 32; i++) b[i] = byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    return b;
}
