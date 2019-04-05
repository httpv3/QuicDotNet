using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class SignatureAlgorithms : Extension
    {
        public const int ArrayLength_NumBytes = 2;
        public const int SignatureAlgorithmLength_NumBytes = 2;

        public List<SignatureScheme> Schemes = new List<SignatureScheme>();

        public SignatureAlgorithms(ReadOnlySpan<byte> data) : base(ExtensionType.SignatureAlgorithms)
        {
            data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextNumber(SignatureAlgorithmLength_NumBytes, out var val);

                if (Enum.IsDefined(typeof(SignatureScheme), (ushort)val))
                    Schemes.Add((SignatureScheme)Enum.ToObject(typeof(SignatureScheme), (ushort)val));
            }
        }
    }
}
