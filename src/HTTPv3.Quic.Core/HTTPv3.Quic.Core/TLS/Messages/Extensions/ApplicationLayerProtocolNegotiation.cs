using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class ApplicationLayerProtocolNegotiation : Extension
    {
        public const int ArrayLength_NumBytes = 2;
        public const int ProtocolLength_NumBytes = 1;

        public List<byte[]> Protocols = new List<byte[]>();

        public ApplicationLayerProtocolNegotiation(ReadOnlySpan<byte> data) : base(ExtensionType.ApplicationLayerProtocolNegotiation)
        {
            data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextTLSVariableLength(ProtocolLength_NumBytes, out var pBytes);
                Protocols.Add(pBytes.ToArray());
            }
        }
    }
}
