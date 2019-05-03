using System;
using System.Collections.Generic;
using System.Text;
using HTTPv3.Quic.Messages.Extensions;

namespace HTTPv3.Quic.TLS
{
    internal class Connection
    {
        public ApplicationKeys ApplicationKeys;
        public HandshakeKeys HandshakeKeys;
        public InitialKeys InitialKeys;

        public Connection(byte[] clientChosenDestinationId, bool isServer)
        {
            InitialKeys = new InitialKeys(clientChosenDestinationId, isServer);
        }

        public void Process(byte[] bytes)
        {

        }

        internal void WriteClientHello(Span<byte> buffer, string serverName)
        {
            
        }
    }
}
