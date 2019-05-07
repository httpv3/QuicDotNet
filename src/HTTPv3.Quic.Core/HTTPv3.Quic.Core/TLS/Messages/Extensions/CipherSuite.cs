using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    // The Transport Layer Security (TLS) Protocol Version 1.3
    // 4.1.2.  Client Hello
    // https://tools.ietf.org/html/rfc8446#section-4.1.2
    public enum CipherSuite : ushort
    {
        NA = 0,
        TLS_AES_128_GCM_SHA256 = 0x1301,
        TLS_AES_256_GCM_SHA384 = 0x1302,
        TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    }

    internal static class CipherSuiteExtensions
    {
        public const int ArrayLength_NumBytes = 2;
        public const int Length_NumBytes = 2;

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, out CipherSuite cs)
        {
            var ret = bytesIn.Read(Length_NumBytes, out ushort val);

            cs = ParseValue(val);

            return ret;
        }

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, in List<CipherSuite> list)
        {
            var ret = bytesIn.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while (!arrData.IsEmpty)
            {
                arrData = arrData.Read(out CipherSuite g);
                list.Add(g);
            }

            return ret;
        }

        public static CipherSuite ParseValue(ushort value)
        {
            if (Enum.IsDefined(typeof(CipherSuite), value))
                return (CipherSuite)value;

            return CipherSuite.NA;
        }

        public static Span<byte> Write(this in Span<byte> buffer, CipherSuite cs)
        {
            return buffer.Write((ushort)cs, Length_NumBytes);
        }

        public static Span<byte> Write(this in Span<byte> buffer, in List<CipherSuite> list)
        {
            var arrDataStart = buffer.Slice(ArrayLength_NumBytes);
            var arrDataCurrent = arrDataStart;

            foreach (var cs in list)
                if (cs != CipherSuite.NA)
                    arrDataCurrent = arrDataCurrent.Write(cs);

            int arrLen = arrDataStart.Length - arrDataCurrent.Length;

            buffer.Write(arrLen, ArrayLength_NumBytes);

            return arrDataCurrent;
        }
    }
}
