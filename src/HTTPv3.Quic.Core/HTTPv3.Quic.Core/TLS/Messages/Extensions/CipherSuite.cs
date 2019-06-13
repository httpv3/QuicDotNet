using HTTPv3.Quic.Extensions;
using System;
using System.Collections.Generic;

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
            var ret = bytesIn.ReadNextTLSVariableLength(ArrayLength_NumBytes, out ReadOnlySpan<byte> arrData);

            while (!arrData.IsEmpty)
            {
                arrData = arrData.Read(out CipherSuite item);
                list.Add(item);
            }

            return ret;
        }

        public static CipherSuite ParseValue(ushort value)
        {
            if (Enum.IsDefined(typeof(CipherSuite), value))
                return (CipherSuite)value;

            return CipherSuite.NA;
        }

        public static Span<byte> Write(this in Span<byte> buffer, CipherSuite cs) => buffer.Write((ushort)cs, Length_NumBytes);

        public static Span<byte> Write(this in Span<byte> buffer, List<CipherSuite> list)
        {
            return buffer.WriteVector(ArrayLength_NumBytes, (buf, state) =>
            {
                foreach (var item in list)
                    if (item != CipherSuite.NA)
                        buf = buf.Write(item);

                state.EndLength = buf.Length;
            });
        }
    }
}
