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
        public EncryptionState EncryptionState { get; private set; } = EncryptionState.Initial;

        public ConnectionId MyConnectionId;
        public ConnectionId RemoteConnectionId;
        public IPEndPoint RemoteEndPoint;

        private InitialKeys InitialKeys;

        internal Connection() { }

        internal void CreateInitialKeys(ConnectionId clientChosenDestinationId, bool isServer)
        {
            InitialKeys = new InitialKeys(clientChosenDestinationId.ConnectionIdBytes, isServer);
        }

        internal EncryptionKeys CurrentKeys
        {
            get
            {
                switch (EncryptionState)
                {
                    case EncryptionState.Initial:
                        return InitialKeys.EncryptionKeys;
                }

                return null;
            }
        }
    }
}
