using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class ServerName
    {
        public const int NameLength_NumBytes = 2;
        public const byte HostNameType = 0;

        public byte[] Name = new byte[0];

        public ServerName(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty)
                return;

            data = data.Read(out byte type)
                       .ReadNextTLSVariableLength(NameLength_NumBytes, out var name);

            if (type == HostNameType)
            {
                Name = name.ToArray();
            }
        }
    }
}
