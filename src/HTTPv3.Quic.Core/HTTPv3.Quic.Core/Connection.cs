using HTTPv3.Quic.TLS;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace HTTPv3.Quic
{
    public class Connection
    {
        public ConnectionState ConnectionState { get; private set; } = ConnectionState.NotConnected;

        public ClientConnectionId ClientConnectionId;
        public ServerConnectionId ServerConnectionId;
        public IPEndPoint RemoteEndPoint;

        internal ApplicationKeys ApplicationKeys;
        internal HandshakeKeys HandshakeKeys;
        internal InitialKeys InitialKeys;

        public bool IsServer = false;

        public ConnectionId MyConnectionId {  get { return IsServer ? ServerConnectionId as ConnectionId : ClientConnectionId as ConnectionId; } }

        internal Connection() { }

        internal void CreateInitialKeys(ServerConnectionId clientChosenServerId, bool isServer)
        {
            IsServer = isServer;
            InitialKeys = new InitialKeys(clientChosenServerId.ConnectionIdBytes, isServer);
        }
    }
}
