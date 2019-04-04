using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class ApplicationLayerProtocolNegotiation : Extension
    {
        public const int ArrayLengthNumBytes = 2;
        public const int ProtocolLengthNumBytes = 1;

        public List<byte[]> Protocols = new List<byte[]>();

        public ApplicationLayerProtocolNegotiation(ReadOnlySpan<byte> data) : base(ExtensionType.ApplicationLayerProtocolNegotiation)
        {
            data.ReadNextTLSVariableLength(ArrayLengthNumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextTLSVariableLength(ProtocolLengthNumBytes, out var pBytes);
                Protocols.Add(pBytes.ToArray());
            }
        }
    }
}
