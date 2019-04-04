using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class SignatureAlgorithms : Extension
    {
        public const int ArrayLengthNumBytes = 2;
        public const int SignatureAlgorithmLengthNumBytes = 2;

        public List<SignatureScheme> Schemes = new List<SignatureScheme>();

        public SignatureAlgorithms(ReadOnlySpan<byte> data) : base(ExtensionType.SignatureAlgorithms)
        {
            data.ReadNextTLSVariableLength(ArrayLengthNumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextNumber(SignatureAlgorithmLengthNumBytes, out var val);

                if (Enum.IsDefined(typeof(SignatureScheme), (ushort)val))
                    Schemes.Add((SignatureScheme)Enum.ToObject(typeof(SignatureScheme), (ushort)val));
            }
        }
    }
}
