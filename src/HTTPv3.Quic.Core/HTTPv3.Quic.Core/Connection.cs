using HTTPv3.Quic.Messages.Extensions;
using HTTPv3.Quic.Security;
using HTTPv3.Quic.TLS;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HTTPv3.Quic
{
    public class Connection
    {
        public CancellationToken cancel = new CancellationToken();

        public ConnectionState ConnectionState { get; private set; } = ConnectionState.NotConnected;

        public ClientConnectionId ClientConnectionId;
        public ServerConnectionId ServerConnectionId;
        public IPEndPoint RemoteEndPoint;
        public string ServerName;

        internal ApplicationKeys ApplicationKeys;
        internal HandshakeKeys HandshakeKeys;
        internal InitialKeys InitialKeys;

        internal TLS.ClientConnection TLSConn;

        public bool IsServer = false;

        public ConnectionId MyConnectionId {  get { return IsServer ? ServerConnectionId as ConnectionId : ClientConnectionId as ConnectionId; } }

        private Pipe TLSSender = new Pipe();
        private Pipe TLSReceiver = new Pipe();

        internal Connection(byte[] clientChosenDestinationId, string serverName, bool isServer)
        {
            ServerName = serverName;
            IsServer = isServer;
            TLSConn = new TLS.ClientConnection(TLSSender.Reader, TLSReceiver.Writer, cancel);
        }

        internal async Task SendConnect()
        {
            var buffer = new byte[1500];

            TLSConn.WriteClientHello(buffer, ServerName);
        }
    }
}
