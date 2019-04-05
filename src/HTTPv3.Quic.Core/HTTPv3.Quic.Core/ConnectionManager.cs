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

        public static Connection StartNewConversation()
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

            conn.CreateInitialKeys(conn.RemoteConnectionId, false);

            return conn;
        }

        public static Connection CreateForExisting(ConnectionId myId, ConnectionId remoteId, bool isServer)
        {
            Connection conn = new Connection()
            {
                MyConnectionId = myId,
                RemoteConnectionId = remoteId
            };

            conn.CreateInitialKeys(isServer ? remoteId : myId, isServer);

            connections[myId] = connections[remoteId] = conn;

            return conn;
        }

        public static Connection GetOrCreate(ConnectionId myId, ConnectionId remoteId, bool isServer)
        {
            var conn = Get(myId);
            if (conn != null)
                return conn;

            conn = CreateForExisting(myId, remoteId, isServer);

            return conn;
        }
    }
}
