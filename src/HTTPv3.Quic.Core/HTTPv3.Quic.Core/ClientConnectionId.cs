using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic
{
    public class ClientConnectionId : ConnectionId
    {
        public ClientConnectionId(byte[] connectionIdBytes) : base(connectionIdBytes) { }

        public static ClientConnectionId Generate() => new ClientConnectionId(GenerateBytes(DefaultLength));
        public static ClientConnectionId Generate(int length) => new ClientConnectionId(GenerateBytes(length));
    }
}
