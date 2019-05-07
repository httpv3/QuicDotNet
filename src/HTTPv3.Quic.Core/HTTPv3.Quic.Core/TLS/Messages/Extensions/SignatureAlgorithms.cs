﻿using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class SignatureAlgorithms : List<SignatureScheme>
    {
        public const int ArrayLength_NumBytes = 2;
        public const int SignatureAlgorithmLength_NumBytes = 2;

        public ReadOnlySpan<byte> Parse(in ReadOnlySpan<byte> data)
        {
            var ret = data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while (!arrData.IsEmpty)
            {
                arrData = arrData.Read(SignatureAlgorithmLength_NumBytes, out ushort val);

                Add(ParseValue(val));
            }

            return ret;
        }

        public static SignatureScheme ParseValue(ushort value)
        {
            if (Enum.IsDefined(typeof(SignatureScheme), value))
                return (SignatureScheme)value;

            return SignatureScheme.NA;
        }

        public Span<byte> Write(in Span<byte> buffer)
        {
            var bufCur = buffer.Write(ExtensionType.SupportedVersions);

            var lenStart = bufCur;
            var arrDataStart = lenStart.Slice(Extension.Length_NumBytes + ArrayLength_NumBytes);
            var arrDataCurrent = arrDataStart;

            foreach (var scheme in this)
                if (scheme != SignatureScheme.NA)
                    arrDataCurrent = arrDataCurrent.Write((ushort)scheme, SignatureAlgorithmLength_NumBytes);

            int arrLen = arrDataStart.Length - arrDataCurrent.Length;
            int len = ArrayLength_NumBytes + arrLen;

            lenStart.Write(len, Extension.Length_NumBytes)
                    .Write(arrLen, ArrayLength_NumBytes);

            return arrDataCurrent;
        }
    }
}
