using HTTPv3.Quic.TLS;
using System.Linq;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using HTTPv3.Quic.Messages.Frames;
using System;
using HTTPv3.Quic.Extensions;

namespace HTTPv3.Quic.Messages.Client
{
    internal class ApplicationSender
    {
        public const ushort MAX_DATA = 1200;

        UdpClient udpClient;
        Connection conn;

        IFrameStreamer[] streams;
        AvailableFrameInfo[] availableInfo;

        public ApplicationSender(UdpClient udpClient, Connection conn)
        {
            this.udpClient = udpClient;
            this.conn = conn;
            streams = new IFrameStreamer[] { conn.ApplicationCryptoStream, conn.ApplicationAckStream };
            availableInfo = streams.Select(s => s.AvailableInfo).ToArray();
        }

        private IAsyncEnumerable<AvailableFrameInfo> Streams => streams.Select(s => s.WaitBytesAvailable()).Combine();

        public async Task Run()
        {
            await foreach (var stream in Streams)
            {
                var data = await GetFrameData();
                await SendData(data);
            }
        }

        private async Task<Memory<byte>> GetFrameData()
        {
            Memory<byte> buffer = new byte[MAX_DATA];
            var cur = buffer;

            foreach (var info in availableInfo)
            {
                if (info.Empty) continue;
                if (cur.Length < info.MinimumSize) continue;

                var frame = await info.Streamer.GetFrame(cur.Length);

                cur = frame.Write(cur, false);
            }

            return buffer.Slice(0, buffer.Length - cur.Length);
        }

        private async Task SendData(Memory<byte> data)
        {
            await Task.Yield();
        }
    }
}
