using System.CommandLine;
using System.Net;
using System.Net.Http;
using TqkLibrary.Proxy;
using TqkLibrary.Proxy.Interfaces;
using Vpn2ProxyDemo.CommandModules.Interfaces;

namespace Vpn2ProxyDemo.CommandModules
{
    /// <summary>
    /// Base chung cho mọi command module VPN của demo — **không gắn với protocol hay kiểu credential cụ thể**.
    /// Giữ option chung (<c>--check-url</c>), in header + IP trực tiếp, bắt lỗi, và chạy phần dùng chung
    /// <c>TcpIpStack -> VpnProxySource -> ProxyServer -> HttpClient -> checkip</c>.
    /// <para>
    /// Lớp con tự quyết: option riêng (thêm vào <see cref="Command"/> trong ctor của nó) và cách connect
    /// (<see cref="ConnectAsync"/> đọc <see cref="ParseResult"/> rồi trả về <see cref="VpnTunnel"/>). Thêm một
    /// dạng VPN mới = thêm một lớp con, không phải sửa base.
    /// </para>
    /// </summary>
    internal abstract class CommandModuleBase : ICommandModule
    {
        protected Option<string> CheckUrlOption { get; }

        readonly Command _command;
        public Command Command => _command;

        protected CommandModuleBase(string name, string description)
        {
            _command = new Command(name, description);

            CheckUrlOption = new Option<string>("--check-url")
            {
                Description = "URL kiểm tra IP công cộng.",
                DefaultValueFactory = _ => "https://checkip.amazonaws.com/",
            };
            _command.Options.Add(CheckUrlOption);

            _command.SetAction(InvokeAsync);
        }

        async Task<int> InvokeAsync(ParseResult parseResult, CancellationToken ct)
        {
            string checkUrl = parseResult.GetValue(CheckUrlOption)!;

            PrintHeader(_command.Name, checkUrl);

            // IP thật (không qua VPN) để so sánh.
            await PrintDirectIpAsync(checkUrl);
            Console.WriteLine();

            try
            {
                // Lớp con connect VPN và trả về tunnel (giữ vòng đời kết nối).
                await using VpnTunnel tunnel = await ConnectAsync(parseResult, ct);

                // Phần dùng chung: stack -> IProxySource -> ProxyServer -> HttpClient -> checkip.
                IProxySource source = new VpnProxySource(tunnel.Stack);
                await RunProxyAndCheckIpAsync(_command.Name, source, checkUrl);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  !! {ex.GetType().Name}: {ex.Message}");
                Console.WriteLine();
            }

            Console.WriteLine("Done.");
            return 0;
        }

        /// <summary>Đọc option riêng của lớp con từ <paramref name="parseResult"/>, connect VPN, trả tunnel đã lên.</summary>
        protected abstract Task<VpnTunnel> ConnectAsync(ParseResult parseResult, CancellationToken ct);

        /// <summary>Phần dùng chung: cắm <paramref name="source"/> vào ProxyServer (loopback) rồi HttpClient qua proxy -> check IP.</summary>
        async Task RunProxyAndCheckIpAsync(string tag, IProxySource source, string checkUrl)
        {
            using var proxyServer = new ProxyServer(new IPEndPoint(IPAddress.Loopback, 0), source);
            proxyServer.StartListen();
            int port = proxyServer.IPEndPoint!.Port;
            Console.WriteLine($"[{tag}] local proxy listening at http://127.0.0.1:{port}");

            using var handler = new HttpClientHandler
            {
                Proxy = new WebProxy($"http://127.0.0.1:{port}"),
                UseProxy = true,
            };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(40) };

            string ip = (await http.GetStringAsync(checkUrl)).Trim();
            Console.WriteLine($"[{tag}] checkip qua VPN proxy => {ip}");
            Console.WriteLine();
        }

        static void PrintHeader(string protocol, string checkUrl)
        {
            Console.WriteLine("============================================================");
            Console.WriteLine(" VPN -> IProxySource -> ProxyServer -> HttpClient -> checkip");
            Console.WriteLine("============================================================");
            Console.WriteLine($"Protocol : {protocol}");
            Console.WriteLine($"Target   : {checkUrl}");
            Console.WriteLine();
        }

        static async Task PrintDirectIpAsync(string checkUrl)
        {
            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
                string ip = (await http.GetStringAsync(checkUrl)).Trim();
                Console.WriteLine($"[direct] IP công cộng thật (không VPN) => {ip}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[direct] không lấy được IP thật: {ex.Message}");
            }
        }
    }
}
