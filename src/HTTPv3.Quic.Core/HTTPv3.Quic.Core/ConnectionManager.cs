using System;
using System.Collections.Concurrent;
using System.Text;

namespace HTTPv3.Quic
{
    internal static class ConnectionManager
    {
        static ConcurrentDictionary<ConnectionId, Connection> connections = new ConcurrentDictionary<ConnectionId, Connection>();

        public static Connection Get(ConnectionId connId)
        {
            Connection conn;
            if (connections.TryGetValue(connId, out conn))
                return conn;
            return null;
        }

        public static Connection StartConversation()
        {
            Connection conn = new Connection();

            do
            {
                conn.MyConnectionId = ConnectionId.Generate();
            } while (!connections.TryAdd(conn.MyConnectionId, conn));

            do
            {
                conn.RemoteConnectionId = ConnectionId.Generate();
            } while (!connections.TryAdd(conn.RemoteConnectionId, conn));

            conn.CreateInitialKeys(conn.RemoteConnectionId);

            return conn;
        }

        public static Connection CreateForExisting(ConnectionId myId, ConnectionId remoteId)
        {
            Connection conn = new Connection()
            {
                MyConnectionId = myId,
                RemoteConnectionId = remoteId
            };

            conn.CreateInitialKeys(myId);

            connections[myId] = connections[remoteId] = conn;

            return conn;
        }

        public static Connection GetOrCreate(ConnectionId myId, ConnectionId remoteId)
        {
            var conn = Get(myId);
            if (conn != null)
                return conn;

            conn = CreateForExisting(myId, remoteId);

            return conn;
        }
    }
}
