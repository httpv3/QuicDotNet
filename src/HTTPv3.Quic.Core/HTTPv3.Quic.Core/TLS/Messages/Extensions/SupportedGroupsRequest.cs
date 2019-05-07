using System;
using System.Collections.Generic;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class SupportedGroupsRequest : List<NamedGroup>
    {
        public const int ArrayLength_NumBytes = 2;

        public ReadOnlySpan<byte> Parse(in ReadOnlySpan<byte> data)
        {
            var ret = data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while (!arrData.IsEmpty)
            {
                arrData = arrData.Read(out NamedGroup g);
                Add(g);
            }

            return ret;
        }

        public Span<byte> Write(in Span<byte> buffer)
        {
            var bufCur = buffer.Write(ExtensionType.SupportedGroups);

            var lenStart = bufCur;
            var arrDataStart = lenStart.Slice(Extension.Length_NumBytes + ArrayLength_NumBytes);
            var arrDataCurrent = arrDataStart;

            foreach (var version in this)
                if (version != NamedGroup.NA)
                    arrDataCurrent = arrDataCurrent.Write(version);

            int arrLen = arrDataStart.Length - arrDataCurrent.Length;
            int len = ArrayLength_NumBytes + arrLen;

            lenStart.Write(len, Extension.Length_NumBytes)
                    .Write(arrLen, ArrayLength_NumBytes);

            return arrDataCurrent;
        }
    }
}
