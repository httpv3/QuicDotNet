using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Extensions
{
    internal class TransportParameterNumber : TransportParameter
    {
        public ulong Number;

        public TransportParameterNumber(TransportParameterId type, ReadOnlySpan<byte> data) : base(type)
        {
            data.ReadNextVariableInt(out Number);
        }
    }
}
