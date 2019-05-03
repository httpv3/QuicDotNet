using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class ServerNameList
    {
        public const int ArrayLength_NumBytes = 2;
        public const int NameLength_NumBytes = 2;
        public const byte HostNameType = 0;

        public static string Parse(ReadOnlySpan<byte> data)
        {
            data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextByte(out var type)
                                 .ReadNextTLSVariableLength(NameLength_NumBytes, out var name);

                if (type == HostNameType)
                    return Encoding.ASCII.GetString(name.ToArray());
            }

            return null;
        }
    }
}
