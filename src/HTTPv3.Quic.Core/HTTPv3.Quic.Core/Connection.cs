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
        private const int MINIMUM_INITIAL_MESSAGE_SIZE = 1200;

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
            await Task.Delay(1);

            var buffer = new byte[1500];

            WriteConnect(buffer, out int len);


        }

        internal void WriteConnect(in Span<byte> buffer, out int length)
        {
            

            var curSpan = TLSConn.WriteClientHello(buffer, ServerName, TransportParameters.Default.ToUnknownExtension());

            length = buffer.Length - curSpan.Length;

            if (length > MINIMUM_INITIAL_MESSAGE_SIZE) //No Padding needed.
                return;

            buffer.PadToLength(length, MINIMUM_INITIAL_MESSAGE_SIZE);
            length = MINIMUM_INITIAL_MESSAGE_SIZE;
        }
    }
}
