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
                conn.ClientConnectionId = new ClientConnectionId(ConnectionId.Generate());
            } while (!connections.TryAdd(conn.ClientConnectionId, conn));

            do
            {
                conn.ServerConnectionId = new ServerConnectionId(ConnectionId.Generate());
            } while (!connections.TryAdd(conn.ServerConnectionId, conn));

            conn.CreateInitialKeys(conn.ServerConnectionId, false);

            return conn;
        }

        public static Connection CreateForExisting(ClientConnectionId clientId, ServerConnectionId serverId, bool isServer)
        {
            Connection conn = new Connection()
            {
                ClientConnectionId = clientId,
                ServerConnectionId = serverId
            };

            conn.CreateInitialKeys(serverId, isServer);

            connections[clientId] = connections[serverId] = conn;

            return conn;
        }

        public static Connection GetOrCreate(ClientConnectionId clientId, ServerConnectionId serverId, bool isServer)
        {
            var conn = Get(clientId);
            if (conn != null)
                return conn;

            conn = Get(serverId);
            if (conn != null)
                return conn;

            conn = CreateForExisting(clientId, serverId, isServer);

            return conn;
        }
    }
}
