using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class ServerNameList : Extension
    {
        public const int ArrayLength_NumBytes = 2;
        public const int NameLength_NumBytes = 2;
        public const byte HostNameType = 0;

        public byte[] Name;

        public ServerNameList(ReadOnlySpan<byte> data) : base(ExtensionType.ServerName)
        {
            data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextByte(out var type)
                                 .ReadNextTLSVariableLength(NameLength_NumBytes, out var name);

                if (type == HostNameType)
                {
                    Name = name.ToArray();
                    return;
                }
            }
        }
    }
}
