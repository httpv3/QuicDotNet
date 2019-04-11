using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class ServerName : Extension
    {
        public const int NameLength_NumBytes = 2;
        public const byte HostNameType = 0;

        public byte[] Name = new byte[0];

        public ServerName(ReadOnlySpan<byte> data) : base(ExtensionType.ServerName)
        {
            if (data.IsEmpty)
                return;

            data = data.ReadNextByte(out var type)
                       .ReadNextTLSVariableLength(NameLength_NumBytes, out var name);

            if (type == HostNameType)
            {
                Name = name.ToArray();
            }
        }
    }
}
