using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal enum PskKeyExchangeMode : byte
    {
        PSKOnlyKeyEstablishment = 0,
        PSKwithDheKeyEstablishment = 1,

        NA = 0xff,
    }

    internal static class PskKeyExchangeModeExtensions
    {
        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, out PskKeyExchangeMode pv)
        {
            var ret = bytesIn.Read(out byte val);

            pv = ParseValue(val);

            return ret;
        }

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, in List<PskKeyExchangeMode> list)
        {
            var ret = bytesIn.Read(out byte length);

            for (int i = 0; i < length; i ++)
            {
                ret = ret.Read(out PskKeyExchangeMode mode);
                list.Add(mode);
            }

            return ret;
        }

        public static PskKeyExchangeMode ParseValue(byte value)
        {
            if (Enum.IsDefined(typeof(PskKeyExchangeMode), value))
                return (PskKeyExchangeMode)value;

            return PskKeyExchangeMode.NA;
        }

        public static Span<byte> Write(this in Span<byte> buffer, PskKeyExchangeMode mode)
        {
            return buffer.Write((byte)mode);
        }

        public static Span<byte> Write(this in Span<byte> buffer, List<PskKeyExchangeMode> list)
        {
            var cur = buffer.Write((byte)(list.Count));

            foreach (var pv in list)
                cur = cur.Write(pv);

            return cur;
        }
    }
}
