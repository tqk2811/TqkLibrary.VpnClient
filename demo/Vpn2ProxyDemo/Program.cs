using System.CommandLine;
using System.Text;
using Vpn2ProxyDemo.CommandModules;

namespace Vpn2ProxyDemo
{
    // Demo: VPN -> IProxySource -> ProxyServer -> HttpClient -> checkip.amazonaws.com
    // Args xử lý bằng System.CommandLine theo mẫu ICommandModule (mỗi protocol là 1 subcommand):
    //   Vpn2ProxyDemo sstp | l2tp   [--host ... --user ... --pass ... --check-url ...]
    internal static class Program
    {
        static Task<int> Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            var root = new RootCommand("Demo: VPN (MS-SSTP / L2TP-IPsec) -> IProxySource -> ProxyServer -> HttpClient -> checkip.")
            {
                new SstpCommandModule().Command,
                new L2tpCommandModule().Command,
            };

            return root.Parse(args).InvokeAsync();
        }
    }
}
