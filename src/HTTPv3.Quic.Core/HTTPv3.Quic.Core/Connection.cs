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
        public EncryptionState EncryptionState { get; internal set; } = EncryptionState.Initial;

        public ClientConnectionId ClientConnectionId;
        public ServerConnectionId ServerConnectionId;
        public IPEndPoint RemoteEndPoint;

        private InitialKeys InitialKeys;
        internal HandshakeKeys HandshakeKeys;

        internal Connection() { }

        internal void CreateInitialKeys(ServerConnectionId clientChosenServerId, bool isServer)
        {
            InitialKeys = new InitialKeys(clientChosenServerId.ConnectionIdBytes, isServer);
        }

        internal EncryptionKeys CurrentKeys
        {
            get
            {
                switch (EncryptionState)
                {
                    case EncryptionState.Initial:
                        return InitialKeys.EncryptionKeys;
                    case EncryptionState.Handshake:
                        return HandshakeKeys.EncryptionKeys;
                }

                return null;
            }
        }
    }
}
