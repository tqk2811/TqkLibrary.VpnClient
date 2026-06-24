using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Drivers.Vtun;
using TqkLibrary.VpnClient.Drivers.Vtun.Config;
using TqkLibrary.VpnClient.Drivers.Vtun.Transport;
using TqkLibrary.VpnClient.IpStack;

// Live full-tunnel harness for the vtun driver against a REAL vtund 3.0.4 daemon.
// args: <serverHost> <port> <hostName> <password> <tunnelAddr/cidr> <peerAddr>
if (args.Length < 6)
{
    Console.WriteLine("usage: harness <serverHost> <port> <hostName> <password> <tunnelAddr/cidr> <peerAddr>");
    return 1;
}

string serverHost = args[0];
int port = int.Parse(args[1]);
string hostName = args[2];
string password = args[3];
string[] addrParts = args[4].Split('/');
IPAddress tunnelAddr = IPAddress.Parse(addrParts[0]);
int prefix = addrParts.Length > 1 ? int.Parse(addrParts[1]) : 24;
IPAddress peerAddr = IPAddress.Parse(args[5]);

using var loggerFactory = LoggerFactory.Create(b => b.AddSimpleConsole(o => { o.SingleLine = true; o.TimestampFormat = "HH:mm:ss "; }).SetMinimumLevel(LogLevel.Debug));

var config = new VtunConfig
{
    HostName = hostName,
    Password = password,
    TunnelAddress = tunnelAddr,
    PrefixLength = prefix,
    PeerAddress = peerAddr,
    Mtu = 1450,
};

var factory = new VtunSocketTransportFactory();
var vpn = new VtunConnection(serverHost, port, config, factory, loggerFactory: loggerFactory);

try
{
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
    Console.WriteLine($"[*] connecting to vtund {serverHost}:{port} host='{hostName}' (TCP, challenge-response) ...");
    await vpn.ConnectAsync(cts.Token);
    Console.WriteLine($"[+] tunnel up. server flags = {vpn.ServerFlags}, tunnel IP = {tunnelAddr}/{prefix}, peer = {peerAddr}, mtu = {vpn.PacketChannel.Mtu}");

    var stack = new TcpIpStack(vpn.PacketChannel, tunnelAddr);

    // ICMP both ways: ping the server's tunnel IP through the tunnel and wait for the echo reply.
    int ok = 0;
    for (int i = 1; i <= 4; i++)
    {
        try
        {
            using var pingCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            PingReply reply = await stack.PingAsync(peerAddr, default, pingCts.Token);
            Console.WriteLine($"[ping {i}] reply from {peerAddr}: {reply.RoundTripTime.TotalMilliseconds:F1} ms ({reply.Data.Length} bytes)");
            ok++;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ping {i}] FAILED: {ex.GetType().Name}: {ex.Message}");
        }
        await Task.Delay(500);
    }

    Console.WriteLine(ok > 0
        ? $"[✓✓] FULL-TUNNEL LIVE OK — {ok}/4 ICMP echo replies through vtund (2-way ICMP confirmed)"
        : "[✗] no ICMP echo reply through the tunnel");
    await vpn.DisposeAsync();
    return ok > 0 ? 0 : 3;
}
catch (Exception ex)
{
    Console.WriteLine($"[✗] connect failed: {ex.GetType().Name}: {ex.Message}");
    await vpn.DisposeAsync();
    return 2;
}
