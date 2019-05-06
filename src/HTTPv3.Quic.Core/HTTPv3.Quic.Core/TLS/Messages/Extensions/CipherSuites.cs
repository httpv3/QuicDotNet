using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    // The Transport Layer Security (TLS) Protocol Version 1.3
    // 4.1.2.  Client Hello
    // https://tools.ietf.org/html/rfc8446#section-4.1.2
    internal class CipherSuites : List<CipherSuite>
    {
        public const int ArrayLength_NumBytes = 2;
        public const int CipherSuiteLength_NumBytes = 2;

        public ReadOnlySpan<byte> Parse(in ReadOnlySpan<byte> data)
        {
            var ret = data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextNumber(CipherSuiteLength_NumBytes, out var val);

                Add(ParseValue(val));
            }

            return ret;
        }

        public static CipherSuite ParseValue(uint value)
        {
            if (Enum.IsDefined(typeof(CipherSuite), (ushort)value))
                return (CipherSuite)Enum.ToObject(typeof(CipherSuite), (ushort)value);

            return CipherSuite.NA;
        }

        public Span<byte> Write(in Span<byte> buffer)
        {
            var arrDataStart = buffer.Slice(ArrayLength_NumBytes);
            var arrDataCurrent = arrDataStart;

            foreach (var version in this)
                if (version != CipherSuite.NA)
                    arrDataCurrent = arrDataCurrent.Write((ushort)version);

            buffer.Write((ushort)(arrDataStart.Length - arrDataCurrent.Length));

            return arrDataCurrent;
        }
    }
    public enum CipherSuite : ushort
    {
        NA = 0,
        TLS_AES_128_GCM_SHA256 = 0x1301,
        TLS_AES_256_GCM_SHA384 = 0x1302,
        TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    }
}
