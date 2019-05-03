using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class SignatureAlgorithms
    {
        public const int ArrayLength_NumBytes = 2;
        public const int SignatureAlgorithmLength_NumBytes = 2;

        public static List<SignatureScheme> Parse(ReadOnlySpan<byte> data)
        {
            List<SignatureScheme> ret = new List<SignatureScheme>();

            data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextNumber(SignatureAlgorithmLength_NumBytes, out var val);

                if (Enum.IsDefined(typeof(SignatureScheme), (ushort)val))
                    ret.Add((SignatureScheme)Enum.ToObject(typeof(SignatureScheme), (ushort)val));
            }

            return ret;
        }
    }
}
