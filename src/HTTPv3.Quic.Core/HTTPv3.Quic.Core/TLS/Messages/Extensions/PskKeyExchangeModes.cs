using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class PskKeyExchangeModes
    {
        public const int ArrayLength_NumBytes = 1;

        public static List<PskKeyExchangeMode> Parse(ReadOnlySpan<byte> data)
        {
            List<PskKeyExchangeMode> ret = new List<PskKeyExchangeMode>();

            data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextByte(out var val);

                if (Enum.IsDefined(typeof(PskKeyExchangeMode), val))
                    ret.Add((PskKeyExchangeMode)Enum.ToObject(typeof(PskKeyExchangeMode), val));
            }

            return ret;
        }
    }
}
