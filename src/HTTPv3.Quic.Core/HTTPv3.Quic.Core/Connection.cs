using HTTPv3.Quic.Messages.Extensions;
using HTTPv3.Quic.TLS;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace HTTPv3.Quic
{
    public class Connection
    {
        public ConnectionState ConnectionState { get; private set; } = ConnectionState.NotConnected;

        public ClientConnectionId ClientConnectionId;
        public ServerConnectionId ServerConnectionId;
        public IPEndPoint RemoteEndPoint;
        public string ServerName;

        internal TLS.Connection TLSConn;

        public bool IsServer = false;

        public ConnectionId MyConnectionId {  get { return IsServer ? ServerConnectionId as ConnectionId : ClientConnectionId as ConnectionId; } }

        internal Connection(byte[] clientChosenDestinationId, bool isServer)
        {
            IsServer = isServer;
            TLSConn = new TLS.Connection(clientChosenDestinationId, isServer);
        }

        internal async Task SendConnect()
        {
            var buffer = new byte[1500];

            TLSConn.WriteClientHello(buffer, ServerName);
        }
    }
}
