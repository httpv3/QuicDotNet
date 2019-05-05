using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class ApplicationLayerProtocolNegotiation
    {
        public const int ArrayLength_NumBytes = 2;
        public const int ProtocolLength_NumBytes = 1;

        public static List<byte[]> Parse(ReadOnlySpan<byte> data)
        {
            List<byte[]> ret = new List<byte[]>();

            data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextTLSVariableLength(ProtocolLength_NumBytes, out var pBytes);
                ret.Add(pBytes.ToArray());
            }

            return ret;
        }
    }
}
