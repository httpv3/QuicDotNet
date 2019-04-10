using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class KeyShareClientHello : Extension
    {
        public const int ArrayLength_NumBytes = 2;
        public const int SignatureAlgorithmLength_NumBytes = 2;

        public List<KeyShare> SharedKeys = new List<KeyShare>();

        public KeyShareClientHello(ReadOnlySpan<byte> data) : base(ExtensionType.KeyShare)
        {
            data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                SharedKeys.Add(new KeyShare(ref arrData));
            }
        }
    }
}
