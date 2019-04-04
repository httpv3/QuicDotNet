using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class ServerName : Extension
    {
        public const int ArrayLengthNumBytes = 2;
        public const int NameLengthNumBytes = 2;
        public const byte HostNameType = 0;

        public byte[] Name;

        public ServerName(ReadOnlySpan<byte> data) : base(ExtensionType.ServerName)
        {
            data.ReadNextTLSVariableLength(ArrayLengthNumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextByte(out var type)
                                 .ReadNextTLSVariableLength(NameLengthNumBytes, out var name);

                if (type == HostNameType)
                {
                    Name = name.ToArray();
                    return;
                }
            }
        }
    }
}
