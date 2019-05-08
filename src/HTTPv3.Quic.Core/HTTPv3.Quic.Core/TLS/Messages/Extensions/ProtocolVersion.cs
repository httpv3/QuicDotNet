using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal enum ProtocolVersion : ushort
    {
        NA = 0x0000,
        TLSv1_0 = 0x0301,
        TLSv1_1 = 0x0302,
        TLSv1_2 = 0x0303,
        TLSv1_3 = 0x0304,
    }

    internal static class ProtocolVersionExtensions
    {
        public const int ArrayLength_NumBytes = 1;
        public const int Length_NumBytes = 2;

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, out ProtocolVersion pv)
        {
            var ret = bytesIn.Read(Length_NumBytes, out ushort val);

            pv = ParseValue(val);

            return ret;
        }

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, in List<ProtocolVersion> list)
        {
            var ret = bytesIn.Read(out byte length);

            for (int i = 0; i < length; i += Length_NumBytes)
            {
                ret = ret.Read(out ProtocolVersion pv);
                list.Add(pv);
            }

            return ret;
        }

        public static ProtocolVersion ParseValue(ushort value)
        {
            if (Enum.IsDefined(typeof(ProtocolVersion), value))
                return (ProtocolVersion)value;

            return ProtocolVersion.NA;
        }

        public static Span<byte> Write(this in Span<byte> buffer, ProtocolVersion pv)
        {
            return buffer.Write((ushort)pv, Length_NumBytes);
        }

        public static Span<byte> Write(this in Span<byte> buffer, in List<ProtocolVersion> list)
        {
            var cur = buffer.Write((byte)(list.Count * Length_NumBytes));

            foreach (var pv in list)
                cur = cur.Write(pv);

            return cur;
        }
    }
}
