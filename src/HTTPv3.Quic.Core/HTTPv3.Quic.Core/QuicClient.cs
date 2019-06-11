using System;
using System.IO.Pipelines;
using System.Linq;
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

            var addresses = Dns.GetHostAddresses(serverName);
            var remoteEndPoint = new IPEndPoint(addresses.First(a => a.AddressFamily == AddressFamily.InterNetwork), port);

            udpClient = new UdpClient();
            udpClient.Connect(remoteEndPoint);

            conn = new Connection(serverConn.ConnectionIdBytes, serverName, false, udpClient, cancel)
            {
                ClientConnectionId = ClientConnectionId.Generate(),
                ServerConnectionId = serverConn,
                IsServer = false,
            };

            //Pipe p = new Pipe();
            //p.Reader.
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
    }
}
