using System;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace HTTPv3.Quic
{
    public class QuicClient
    {
        public CancellationToken cancel = new CancellationToken();

        Connection conn;
        UdpClient udpClient;

        public QuicClient(string serverName, short port)
        {
            var serverConn = ServerConnectionId.Generate();

            conn = new Connection(serverConn.ConnectionIdBytes, serverName, false, cancel)
            {
                ClientConnectionId = ClientConnectionId.Generate(),
                ServerConnectionId = serverConn,
                IsServer = false,
            };
            conn.Sender = Send;

            var addresses = Dns.GetHostAddresses(serverName);
            var remoteEndPoint = new IPEndPoint(addresses[0], port);

            udpClient = new UdpClient();
            udpClient.Connect(remoteEndPoint);

            //Pipe p = new Pipe();
            //p.Reader.
        }

        internal async ValueTask Send(byte[] bytes, int length)
        {
            await udpClient.SendAsync(bytes, length);
        }

        public async Task<ConnectionState> Connect()
        {
            await conn.SendConnect();

            return conn.ConnectionState;
        }

        public Task<string> Request(string url)
        {
            return null;
        }

        private async Task StartListening()
        {
            var tcs = new TaskCompletionSource<decimal>();

            cancel.Register(() =>
            {
                tcs.TrySetCanceled();
            });

            while (!cancel.IsCancellationRequested)
            {
                var t = udpClient.ReceiveAsync();

                await Task.WhenAny(t, tcs.Task);
                if (cancel.IsCancellationRequested)
                    return;

                var res = t.Result;

                //res.Buffer
            }
        }
    }
}
