using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class KeyShares : Extension
    {
        public const int ArrayLengthNumBytes = 2;
        public const int SignatureAlgorithmLengthNumBytes = 2;

        public List<KeyShare> SharedKeys = new List<KeyShare>();

        public KeyShares(ReadOnlySpan<byte> data) : base(ExtensionType.KeyShare)
        {
            data.ReadNextTLSVariableLength(ArrayLengthNumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                SharedKeys.Add(new KeyShare(ref arrData));
            }
        }
    }
}
