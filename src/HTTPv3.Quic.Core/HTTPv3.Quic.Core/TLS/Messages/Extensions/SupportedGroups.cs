using System;
using System.Collections.Generic;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class SupportedGroups : List<NamedGroup>
    {
        public const int ArrayLength_NumBytes = 2;
        public const int NamedGroupLength_NumBytes = 2;

        public ReadOnlySpan<byte> Parse(in ReadOnlySpan<byte> data)
        {
            var ret = data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while (!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextNumber(NamedGroupLength_NumBytes, out var val);

                Add(ParseValue(val));
            }

            return ret;
        }

        public static NamedGroup ParseValue(uint value)
        {
            if (Enum.IsDefined(typeof(NamedGroup), (ushort)value))
                return (NamedGroup)Enum.ToObject(typeof(NamedGroup), (ushort)value);

            return NamedGroup.NA;
        }

        public Span<byte> Write(in Span<byte> buffer)
        {
            var arrDataStart = buffer.Slice(ArrayLength_NumBytes);
            var arrDataCurrent = arrDataStart;

            foreach (var version in this)
                if (version != NamedGroup.NA)
                    arrDataCurrent = arrDataCurrent.Write((ushort)version);

            buffer.Write((ushort)(arrDataStart.Length - arrDataCurrent.Length));

            return arrDataCurrent;
        }
    }
}
