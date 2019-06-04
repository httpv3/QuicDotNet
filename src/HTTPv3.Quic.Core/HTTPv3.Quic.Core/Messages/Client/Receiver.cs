using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.Messages.Frames;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace HTTPv3.Quic.Messages.Client
{
    internal class Receiver
    {
        UdpClient udpClient;
        Connection conn;

        public Receiver(UdpClient udpClient, Connection conn)
        {
            this.udpClient = udpClient;
            this.conn = conn;
        }

        private async IAsyncEnumerable<InboundDatagram> GetDatagrams()
        {
            var tcs = new TaskCompletionSource<decimal>();

            conn.Cancel.Register(() =>
            {
                tcs.TrySetCanceled();
            });

            while (!conn.Cancel.IsCancellationRequested)
            {
                var t = udpClient.ReceiveAsync();

                await Task.WhenAny(t, tcs.Task);
                if (conn.Cancel.IsCancellationRequested)
                    break;

                var res = t.Result;

                yield return new InboundDatagram(res.Buffer);
            }
        }

        public IAsyncEnumerable<IFrame> GetFrames()
        {
            return GetDatagrams().AsPackets().AsDecrypted(conn.KeyManager).AsFrames();
        }
    }
}
