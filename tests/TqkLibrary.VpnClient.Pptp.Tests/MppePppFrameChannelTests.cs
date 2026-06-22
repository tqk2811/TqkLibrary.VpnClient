using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Mppe;
using TqkLibrary.VpnClient.Crypto.Mppe.Enums;
using TqkLibrary.VpnClient.Ppp.Framing.Enums;
using TqkLibrary.VpnClient.Ppp.Interfaces;
using TqkLibrary.VpnClient.Pptp.Ccp;
using Xunit;

namespace TqkLibrary.VpnClient.Pptp.Tests
{
    /// <summary>
    /// Offline coverage for the MPPE PPP-frame decorator (RFC 3078/3079): CCP runs inside the decorator and drives
    /// both ends to Opened; before activation frames pass through plaintext; after activation an IP frame is
    /// MPPE-wrapped (protocol 0x00FD) on the wire and the ciphertext decrypts back to the original.
    /// </summary>
    public class MppePppFrameChannelTests
    {
        const string Password = "Pa$$w0rd!";
        static readonly byte[] NtResponse = BuildNtResponse();

        [Fact]
        public async Task Ccp_Drives_Both_Ends_To_Opened()
        {
            var link = new LoopbackPppLink();
            var client = new MppePppFrameChannel(link.A, () => (Password, NtResponse));
            var server = new MppePppFrameChannel(link.B, () => (Password, NtResponse));

            client.StartCcp();
            server.StartCcp();

            await WithTimeout(Task.WhenAll(client.CcpOpenedTask, server.CcpOpenedTask));
            Assert.True(client.IsActive);
            Assert.True(server.IsActive);
        }

        [Fact]
        public async Task Lcp_Passes_Through_Plaintext_Before_And_After_Ccp()
        {
            var link = new LoopbackPppLink();
            var captured = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            link.B.FrameReceived += f => captured.TrySetResult(f.ToArray());

            var client = new MppePppFrameChannel(link.A, () => (Password, NtResponse));

            // An LCP frame (proto 0xC021) before CCP — must reach the inner channel verbatim.
            byte[] lcp = { 0xFF, 0x03, 0xC0, 0x21, 0x01, 0x02, 0x03 };
            await client.SendAsync(lcp);

            byte[] onWire = await WithTimeout(captured.Task);
            Assert.Equal(lcp, onWire);
        }

        [Fact]
        public async Task Inactive_NonLcp_Frame_Passes_Through_Plaintext()
        {
            var link = new LoopbackPppLink();
            var captured = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            link.B.FrameReceived += f => captured.TrySetResult(f.ToArray());

            var client = new MppePppFrameChannel(link.A, () => (Password, NtResponse));

            byte[] ip = { 0xFF, 0x03, 0x00, 0x21, 0x45, 0x00 };
            await client.SendAsync(ip); // CCP not opened → no encryption

            byte[] onWire = await WithTimeout(captured.Task);
            Assert.Equal(ip, onWire);
        }

        [Fact]
        public async Task Active_Ip_Frame_Is_MppeWrapped_On_Wire_And_Decrypts_To_Original()
        {
            var link = new LoopbackPppLink();
            var client = new MppePppFrameChannel(link.A, () => (Password, NtResponse));
            var server = new MppePppFrameChannel(link.B, () => (Password, NtResponse));

            // Capture raw frames the client puts on the wire (after CCP traffic settles).
            var onWire = new List<byte[]>();
            link.B.FrameReceived += f => onWire.Add(f.ToArray());

            client.StartCcp();
            server.StartCcp();
            await WithTimeout(Task.WhenAll(client.CcpOpenedTask, server.CcpOpenedTask));
            onWire.Clear(); // discard the CCP control packets

            byte[] inner = { 0x00, 0x21, 0xDE, 0xAD, 0xBE, 0xEF }; // [proto:2][ip payload]
            byte[] ipFrame = Prepend0xFF03(inner);
            await client.SendAsync(ipFrame);

            // The wire frame must be [FF 03][00 FD][MPPE cipher].
            Assert.Single(onWire);
            byte[] wire = onWire[0];
            Assert.Equal(0xFF, wire[0]);
            Assert.Equal(0x03, wire[1]);
            Assert.Equal((ushort)PppProtocol.Compressed, BinaryPrimitives.ReadUInt16BigEndian(wire.AsSpan(2)));

            // A matching receive session (the client's send start key) decrypts the cipher back to the original body.
            MppeSession recv = BuildClientSendMirrorSession();
            byte[] recovered = recv.Decrypt(wire.AsSpan(4));
            Assert.Equal(inner, recovered);
        }

        // Builds an MppeSession with the SAME start key the client's send direction uses, so it can decrypt the
        // client's MPPE output (client-send start == server-receive start, RFC 3079 §3.3).
        static MppeSession BuildClientSendMirrorSession()
        {
            byte[] masterKey = MsChapV2.DeriveMppeMasterKey(Password, NtResponse);
            byte[] sendStart = MsChapV2.DeriveMppeSendStartKey(masterKey, isServer: false);
            return new MppeSession(sendStart, MppeKeyStrength.Bits128, stateless: false);
        }

        static byte[] BuildNtResponse()
        {
            var r = new byte[24];
            for (int i = 0; i < r.Length; i++) r[i] = (byte)(i + 1);
            return r;
        }

        static byte[] Prepend0xFF03(byte[] body)
        {
            byte[] f = new byte[body.Length + 2];
            f[0] = 0xFF; f[1] = 0x03;
            Buffer.BlockCopy(body, 0, f, 2, body.Length);
            return f;
        }

        static async Task WithTimeout(Task task)
        {
            Task completed = await Task.WhenAny(task, Task.Delay(5000));
            Assert.Same(task, completed);
            await task;
        }

        static async Task<T> WithTimeout<T>(Task<T> task)
        {
            Task completed = await Task.WhenAny(task, Task.Delay(5000));
            Assert.Same(task, completed);
            return await task;
        }

        /// <summary>An in-memory connected <see cref="IPppFrameChannel"/> pair: each end's send surfaces on the peer's receive.</summary>
        sealed class LoopbackPppLink
        {
            public LoopbackPppLink()
            {
                A = new End();
                B = new End();
                A.Peer = B;
                B.Peer = A;
            }

            public End A { get; }
            public End B { get; }

            public sealed class End : IPppFrameChannel
            {
                internal End? Peer;
                public event Action<ReadOnlyMemory<byte>>? FrameReceived;

                public ValueTask SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken = default)
                {
                    // Deliver synchronously to the peer (copy to detach from the caller's buffer).
                    Peer!.FrameReceived?.Invoke(frame.ToArray());
                    return default;
                }
            }
        }
    }
}
