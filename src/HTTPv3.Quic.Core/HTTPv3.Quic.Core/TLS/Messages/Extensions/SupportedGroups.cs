using System;
using System.Collections.Generic;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class SupportedGroups
    {
        public const int ArrayLength_NumBytes = 2;
        public const int NamedGroupLength_NumBytes = 2;

        public static List<NamedGroup> Parse(ReadOnlySpan<byte> data)
        {
            List<NamedGroup> ret = new List<NamedGroup>();

            data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while (!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextNumber(NamedGroupLength_NumBytes, out var val);

                if (Enum.IsDefined(typeof(NamedGroup), (ushort)val))
                    ret.Add((NamedGroup)Enum.ToObject(typeof(NamedGroup), (ushort)val));
            }

            return ret;
        }
    }
}
