using TqkLibrary.Vpn.Ppp.Enums;
using TqkLibrary.Vpn.Ppp.Models;

namespace TqkLibrary.Vpn.Ppp
{
    /// <summary>
    /// LCP negotiator. Requests MRU and a Magic-Number; accepts the peer's MRU, Magic-Number and an
    /// Authentication-Protocol of MS-CHAPv2 (C223 + algorithm 0x81), and rejects anything else.
    /// </summary>
    public sealed class LcpNegotiator : PppNegotiator
    {
        readonly uint _magic;
        ushort _mru = 1500;
        bool _sendMagic = true;

        /// <summary>Creates an LCP negotiator with the given local magic number.</summary>
        public LcpNegotiator(Action<byte[]> send, uint magic) : base(send)
        {
            _magic = magic;
        }

        /// <summary>Negotiated MRU.</summary>
        public ushort Mru => _mru;

        /// <summary>True if the peer requires MS-CHAPv2 authentication.</summary>
        public bool RequiresMsChapV2 { get; private set; }

        /// <inheritdoc/>
        protected override IReadOnlyList<PppOption> BuildLocalOptions()
        {
            var options = new List<PppOption>
            {
                new PppOption((byte)LcpOptionType.Mru, new[] { (byte)(_mru >> 8), (byte)(_mru & 0xff) }),
            };
            if (_sendMagic)
            {
                options.Add(new PppOption((byte)LcpOptionType.MagicNumber, new[]
                {
                    (byte)(_magic >> 24), (byte)(_magic >> 16), (byte)(_magic >> 8), (byte)_magic,
                }));
            }
            return options;
        }

        /// <inheritdoc/>
        protected override (byte code, IReadOnlyList<PppOption> options) EvaluatePeerRequest(List<PppOption> peerOptions)
        {
            var rejected = new List<PppOption>();
            foreach (PppOption option in peerOptions)
            {
                switch ((LcpOptionType)option.Type)
                {
                    case LcpOptionType.Mru:
                    case LcpOptionType.MagicNumber:
                        break; // accept
                    case LcpOptionType.AuthenticationProtocol:
                        if (IsMsChapV2(option.Data)) RequiresMsChapV2 = true;
                        else rejected.Add(option);
                        break;
                    default:
                        rejected.Add(option);
                        break;
                }
            }

            return rejected.Count > 0
                ? ((byte)PppCode.ConfigureReject, rejected)
                : ((byte)PppCode.ConfigureAck, peerOptions);
        }

        /// <inheritdoc/>
        protected override void OnNak(List<PppOption> nakOptions)
        {
            foreach (PppOption option in nakOptions)
                if (option.Type == (byte)LcpOptionType.Mru && option.Data.Length == 2)
                    _mru = (ushort)((option.Data[0] << 8) | option.Data[1]);
        }

        /// <inheritdoc/>
        protected override void OnReject(List<PppOption> rejectedOptions)
        {
            foreach (PppOption option in rejectedOptions)
                if (option.Type == (byte)LcpOptionType.MagicNumber)
                    _sendMagic = false;
        }

        static bool IsMsChapV2(byte[] data)
            => data.Length >= 3 && data[0] == 0xC2 && data[1] == 0x23 && data[2] == 0x81;
    }
}
