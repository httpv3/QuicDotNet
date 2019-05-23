using System;
using System.IO.Pipelines;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace HTTPv3.Quic
{
    public class QuicClient
    {
        Connection conn;

        public QuicClient(string serverName, short port)
        {
            var serverConn = ServerConnectionId.Generate();

            conn = new Connection(serverConn.ConnectionIdBytes, serverName, false)
            {
                ClientConnectionId = ClientConnectionId.Generate(),
                ServerConnectionId = serverConn,
                IsServer = false,
            };

            var addresses = Dns.GetHostAddresses(serverName);
            var remoteEndPoint = new IPEndPoint(addresses[0], port);

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
