using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class PskKeyExchangeModes : Extension
    {
        public const int ArrayLength_NumBytes = 1;

        public List<PskKeyExchangeMode> Modes = new List<PskKeyExchangeMode>();

        public PskKeyExchangeModes(ReadOnlySpan<byte> data) : base(ExtensionType.PskKeyExchangeModes)
        {
            data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextByte(out var val);

                if (Enum.IsDefined(typeof(PskKeyExchangeMode), val))
                    Modes.Add((PskKeyExchangeMode)Enum.ToObject(typeof(PskKeyExchangeMode), val));
            }
        }
    }
}
