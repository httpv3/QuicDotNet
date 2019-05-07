using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class SupportedVersionsRequest : List<ProtocolVersion>
    {
        public const int ArrayLength_NumBytes = 1;

        public ReadOnlySpan<byte> Parse(in ReadOnlySpan<byte> data)
        {
            var ret = data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while (!arrData.IsEmpty)
            {
                arrData = arrData.Read(out ProtocolVersion pv);

                Add(pv);
            }

            return ret;
        }

        public Span<byte> Write(in Span<byte> buffer)
        {
            var bufCur = buffer.Write(ExtensionType.SupportedVersions);

            var lenStart = bufCur;
            var arrDataStart = lenStart.Slice(Extension.Length_NumBytes + ArrayLength_NumBytes);
            var arrDataCurrent = arrDataStart;

            foreach (var version in this)
                if (version != ProtocolVersion.NA)
                    arrDataCurrent = arrDataCurrent.Write(version);

            int arrLen = arrDataStart.Length - arrDataCurrent.Length;
            int len = ArrayLength_NumBytes + arrLen;

            lenStart.Write(len, Extension.Length_NumBytes)
                    .Write(arrLen, ArrayLength_NumBytes);

            return arrDataCurrent;
        }
    }
}
