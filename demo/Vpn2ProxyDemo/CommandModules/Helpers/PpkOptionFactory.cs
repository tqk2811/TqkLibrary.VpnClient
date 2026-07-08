using System.Text;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Models;

namespace Vpn2ProxyDemo.CommandModules.Helpers
{
    /// <summary>
    /// Dựng <see cref="PpkConfiguration"/> (RFC 8784 Post-quantum Preshared Key) từ các cờ CLI <c>--ppk</c> /
    /// <c>--ppk-id</c> / <c>--ppk-mandatory</c>. Pure/stateless — chỉ chuyển chuỗi option thành cấu hình PPK.
    /// <para>Quy tắc mã hóa bí mật/định danh: chuỗi bắt đầu bằng <c>0x</c> ⇒ phần còn lại là hex byte thô; ngược lại là
    /// UTF-8. <c>--ppk-id</c> trống mặc định <c>"ppk1"</c> (khớp id cấu hình mặc định trên gateway lab).</para>
    /// </summary>
    internal static class PpkOptionFactory
    {
        /// <summary>Định danh PPK mặc định khi có <c>--ppk</c> mà không đặt <c>--ppk-id</c>.</summary>
        public const string DefaultPpkId = "ppk1";

        /// <summary>
        /// Trả <see cref="PpkConfiguration"/> khi <paramref name="ppkSecret"/> không rỗng, hoặc <c>null</c> (không dùng PPK).
        /// <paramref name="ppkId"/> rỗng ⇒ dùng <see cref="DefaultPpkId"/>. <paramref name="mandatory"/> = bắt buộc dùng PPK.
        /// </summary>
        public static PpkConfiguration? Create(string? ppkSecret, string? ppkId, bool mandatory)
        {
            if (string.IsNullOrEmpty(ppkSecret)) return null;
            string id = string.IsNullOrEmpty(ppkId) ? DefaultPpkId : ppkId!;
            return new PpkConfiguration
            {
                Ppk = ParseSecret(ppkSecret!),
                PpkId = ParseSecret(id),
                Mandatory = mandatory,
            };
        }

        /// <summary>Chuỗi <c>0x…</c> ⇒ hex byte; ngược lại ⇒ byte UTF-8.</summary>
        public static byte[] ParseSecret(string value)
        {
            if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return Convert.FromHexString(value.Substring(2));
            return Encoding.UTF8.GetBytes(value);
        }
    }
}
