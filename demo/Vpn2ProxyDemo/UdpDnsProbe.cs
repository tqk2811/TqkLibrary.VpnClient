using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.Vpn.IpStack.Tcp;
using TqkLibrary.Vpn.Sockets;

namespace Vpn2ProxyDemo
{
    /// <summary>
    /// Gửi một truy vấn DNS (bản ghi A) qua UDP xuyên tunnel để đồng thời: (1) xác nhận VPN có định tuyến UDP hay
    /// không và (2) phân giải tên miền thành IPv4. Tự build/parse gói DNS theo RFC 1035 trên
    /// <see cref="VpnUdpClient"/> — KHÔNG dùng <see cref="System.Net.Dns"/> nên truy vấn đi hoàn toàn bên trong VPN.
    /// </summary>
    internal static class UdpDnsProbe
    {
        const ushort DnsPort = 53;
        const ushort TypeA = 1;   // bản ghi A (IPv4)
        const ushort ClassIn = 1; // lớp IN (Internet)

        /// <summary>
        /// Gửi truy vấn A cho <paramref name="domain"/> tới <paramref name="dnsServer"/>:53 qua <paramref name="stack"/>,
        /// gửi lại tối đa <paramref name="attempts"/> lần (mỗi lần chờ <paramref name="perAttemptTimeout"/>).
        /// Nhận được bất kỳ phản hồi UDP nào ⇒ <see cref="UdpDnsProbeResult.UdpSupported"/> = true.
        /// </summary>
        public static async Task<UdpDnsProbeResult> ResolveAsync(
            TcpIpStack stack,
            IPAddress dnsServer,
            string domain,
            int attempts,
            TimeSpan perAttemptTimeout,
            CancellationToken cancellationToken = default)
        {
            ushort transactionId = (ushort)Random.Shared.Next(1, ushort.MaxValue);
            byte[] query = BuildQuery(transactionId, domain);

            VpnUdpClient client = VpnUdpClient.Connect(stack, dnsServer, DnsPort);
            var stopwatch = Stopwatch.StartNew();

            for (int attempt = 1; attempt <= attempts; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                client.Send(query);

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutCts.CancelAfter(perAttemptTimeout);
                try
                {
                    byte[] response = await client.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
                    stopwatch.Stop();

                    // Đã nhận được một datagram UDP từ DNS server ⇒ UDP có chạy, dù parse được A record hay không.
                    TryParseAddresses(response, transactionId, out IReadOnlyList<IPAddress> addresses, out string? error);
                    return new UdpDnsProbeResult(true, addresses, attempt, stopwatch.Elapsed, error);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    // Hết thời gian chờ cho lần thử này (không phải hủy từ ngoài) → gửi lại.
                }
            }

            stopwatch.Stop();
            return new UdpDnsProbeResult(false, Array.Empty<IPAddress>(), attempts, stopwatch.Elapsed,
                $"Không nhận được phản hồi UDP sau {attempts} lần thử.");
        }

        /// <summary>Dựng một gói truy vấn DNS chuẩn (RFC 1035): header + một câu hỏi A/IN, cờ RD bật.</summary>
        static byte[] BuildQuery(ushort transactionId, string domain)
        {
            var buffer = new List<byte>(32);

            // Header (12 byte).
            buffer.Add((byte)(transactionId >> 8));
            buffer.Add((byte)(transactionId & 0xFF));
            buffer.Add(0x01); // cờ: RD = 1 (recursion desired)
            buffer.Add(0x00);
            buffer.Add(0x00); buffer.Add(0x01); // QDCOUNT = 1
            buffer.Add(0x00); buffer.Add(0x00); // ANCOUNT
            buffer.Add(0x00); buffer.Add(0x00); // NSCOUNT
            buffer.Add(0x00); buffer.Add(0x00); // ARCOUNT

            // QNAME: mỗi nhãn = 1 byte độ dài + các byte ASCII.
            foreach (string label in domain.Split('.'))
            {
                if (label.Length == 0) continue;
                byte[] bytes = Encoding.ASCII.GetBytes(label);
                if (bytes.Length > 63)
                    throw new ArgumentException($"Nhãn DNS '{label}' dài quá 63 byte.", nameof(domain));
                buffer.Add((byte)bytes.Length);
                buffer.AddRange(bytes);
            }
            buffer.Add(0x00); // kết thúc QNAME

            buffer.Add((byte)(TypeA >> 8)); buffer.Add((byte)(TypeA & 0xFF));   // QTYPE = A
            buffer.Add((byte)(ClassIn >> 8)); buffer.Add((byte)(ClassIn & 0xFF)); // QCLASS = IN
            return buffer.ToArray();
        }

        /// <summary>
        /// Parse các bản ghi A từ phản hồi DNS. Trả về true nếu khung DNS hợp lệ (kể cả khi không có A record —
        /// khi đó <paramref name="error"/> mô tả lý do, vd rcode != 0). Trả về false nếu khung hỏng/ID không khớp.
        /// </summary>
        static bool TryParseAddresses(byte[] msg, ushort expectedId, out IReadOnlyList<IPAddress> addresses, out string? error)
        {
            addresses = Array.Empty<IPAddress>();
            error = null;
            try
            {
                if (msg.Length < 12) { error = "Phản hồi DNS quá ngắn."; return false; }

                ushort id = (ushort)((msg[0] << 8) | msg[1]);
                if (id != expectedId) { error = "Transaction ID không khớp."; return false; }

                int rcode = msg[3] & 0x0F;
                ushort qdcount = (ushort)((msg[4] << 8) | msg[5]);
                ushort ancount = (ushort)((msg[6] << 8) | msg[7]);

                int pos = 12;
                for (int q = 0; q < qdcount; q++)
                {
                    pos = SkipName(msg, pos);
                    pos += 4; // QTYPE + QCLASS
                }

                var result = new List<IPAddress>();
                for (int a = 0; a < ancount; a++)
                {
                    pos = SkipName(msg, pos);
                    if (pos + 10 > msg.Length) break;
                    int type = (msg[pos] << 8) | msg[pos + 1];
                    int klass = (msg[pos + 2] << 8) | msg[pos + 3];
                    int rdlength = (msg[pos + 8] << 8) | msg[pos + 9];
                    int rdata = pos + 10;
                    if (type == TypeA && klass == ClassIn && rdlength == 4 && rdata + 4 <= msg.Length)
                        result.Add(new IPAddress(new[] { msg[rdata], msg[rdata + 1], msg[rdata + 2], msg[rdata + 3] }));
                    pos = rdata + rdlength;
                }

                addresses = result;
                if (result.Count == 0)
                    error = rcode != 0 ? $"DNS rcode = {rcode} (không phân giải được)." : "Phản hồi không chứa bản ghi A.";
                return true;
            }
            catch (Exception ex)
            {
                error = $"Lỗi parse DNS: {ex.Message}";
                return false;
            }
        }

        /// <summary>Bỏ qua một tên DNS (chuỗi nhãn, kết thúc bằng 0x00 hoặc một con trỏ nén 0xC0), trả về offset kế tiếp.</summary>
        static int SkipName(byte[] msg, int pos)
        {
            while (pos < msg.Length)
            {
                byte len = msg[pos];
                if (len == 0) return pos + 1;
                if ((len & 0xC0) == 0xC0) return pos + 2; // con trỏ nén kết thúc tên (2 byte)
                pos += 1 + len;
            }
            return pos;
        }
    }
}
