using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic
{
    public class ServerConnectionId : ConnectionId
    {
        public ServerConnectionId(byte[] connectionIdBytes) : base(connectionIdBytes) { }

        public static ServerConnectionId Generate(int length = 8) => new ServerConnectionId(GenerateBytes(length));
    }
}
