using System;
using System.Net;
using System.Threading.Tasks;

namespace HTTPv3.Quic
{
    public class QuicClient
    {
        Connection conn;

        public QuicClient(string serverName, short port)
        {
            var addresses = Dns.GetHostAddresses(serverName);
            var serverConn = ServerConnectionId.Generate();

            conn = new Connection(serverConn.ConnectionIdBytes, false)
            {
                ClientConnectionId = ClientConnectionId.Generate(),
                ServerConnectionId = serverConn,
                IsServer = false,
                RemoteEndPoint = new IPEndPoint(addresses[0], port)
            };
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
