using System;
using System.Collections.Generic;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class KeyShare
    {
        public NamedGroup Group;
        public byte[] KeyExchange;
    }

    internal static class KeyShareExtensions
    {
        public const int ArrayLength_NumBytes = 2;
        public const int Length_NumBytes = 2;

        public static ReadOnlySpan<byte> Read(this ReadOnlySpan<byte> bytesIn, out KeyShare namedGroup)
        {
            namedGroup = new KeyShare();

            var ret = bytesIn.Read(out namedGroup.Group)
                          .ReadNextTLSVariableLength(Length_NumBytes, out var keyData);

            namedGroup.KeyExchange = keyData.ToArray();

            return ret;
        }

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, in List<KeyShare> list)
        {
            var ret = bytesIn.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while (!arrData.IsEmpty)
            {
                arrData = arrData.Read(out KeyShare ks);
                list.Add(ks);
            }

            return ret;
        }

        public static Span<byte> Write(this Span<byte> buffer, KeyShare ks)
        {
            return buffer.Write(ks.Group)
                         .WriteTLSVariableLength(Length_NumBytes, ks.KeyExchange);
        }

        public static Span<byte> Write(this in Span<byte> buffer, in List<KeyShare> list)
        {
            var arrDataStart = buffer.Slice(ArrayLength_NumBytes);
            var arrDataCurrent = arrDataStart;

            foreach (var ks in list)
                arrDataCurrent = arrDataCurrent.Write(ks);

            int arrLen = arrDataStart.Length - arrDataCurrent.Length;

            buffer.Write(arrLen, ArrayLength_NumBytes);

            return arrDataCurrent;
        }
    }
}
