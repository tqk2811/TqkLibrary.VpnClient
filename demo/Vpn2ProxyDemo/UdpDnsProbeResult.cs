using System.Collections.Generic;
using System.Net;

namespace Vpn2ProxyDemo
{
    /// <summary>
    /// Kết quả của một lần probe DNS-over-UDP xuyên tunnel (xem <see cref="UdpDnsProbe"/>).
    /// <see cref="UdpSupported"/> trả lời câu hỏi "VPN có định tuyến UDP không"; <see cref="Addresses"/>
    /// là các IPv4 phân giải được từ phản hồi.
    /// </summary>
    internal readonly struct UdpDnsProbeResult
    {
        public UdpDnsProbeResult(bool udpSupported, IReadOnlyList<IPAddress> addresses, int attempts, TimeSpan elapsed, string? error)
        {
            UdpSupported = udpSupported;
            Addresses = addresses;
            Attempts = attempts;
            Elapsed = elapsed;
            Error = error;
        }

        /// <summary>True nếu nhận được ít nhất một phản hồi UDP từ DNS server → tunnel có định tuyến UDP.</summary>
        public bool UdpSupported { get; }

        /// <summary>Các địa chỉ IPv4 (bản ghi A) parse được từ phản hồi; rỗng nếu không có.</summary>
        public IReadOnlyList<IPAddress> Addresses { get; }

        /// <summary>Số lần đã gửi truy vấn trước khi nhận phản hồi (hoặc bỏ cuộc).</summary>
        public int Attempts { get; }

        /// <summary>Thời gian từ lúc gửi tới lúc nhận phản hồi, hoặc tổng thời gian chờ nếu thất bại.</summary>
        public TimeSpan Elapsed { get; }

        /// <summary>Mô tả lỗi/cảnh báo nếu có (vd timeout, rcode != 0, không có bản ghi A); null nếu thành công trọn vẹn.</summary>
        public string? Error { get; }
    }
}
