using HTTPv3.Quic.Extensions;
using System;
using System.Collections.Generic;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    public enum NamedGroup : ushort
    {
        NA = 0x0,

        /* Elliptic Curve Groups  = ECDHE) */
        secp256r1 = 0x0017,
        secp384r1 = 0x0018,
        secp521r1 = 0x0019,
        x25519 = 0x001D,
        x448 = 0x001E,

        /* Finite Field Groups  = DHE) */
        ffdhe2048 = 0x0100,
        ffdhe3072 = 0x0101,
        ffdhe4096 = 0x0102,
        ffdhe6144 = 0x0103,
        ffdhe8192 = 0x0104,
    }

    internal static class NamedGroupExtensions
    {
        public const int ArrayLength_NumBytes = 2;
        public const int Length_NumBytes = 2;

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, out NamedGroup namedGroup)
        {
            var ret = bytesIn.Read(Length_NumBytes, out ushort val);

            namedGroup = ParseValue(val);

            return ret;
        }

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, in List<NamedGroup> list)
        {
            var ret = bytesIn.ReadNextTLSVariableLength(ArrayLength_NumBytes, out ReadOnlySpan<byte> arrData);

            while (!arrData.IsEmpty)
            {
                arrData = arrData.Read(out NamedGroup item);
                list.Add(item);
            }

            return ret;
        }

        public static NamedGroup ParseValue(ushort value)
        {
            if (Enum.IsDefined(typeof(NamedGroup), value))
                return (NamedGroup)value;

            return NamedGroup.NA;
        }

        public static Span<byte> Write(this in Span<byte> buffer, NamedGroup value)
        {
            return buffer.Write((ushort)value, Length_NumBytes);
        }

        public static Span<byte> Write(this in Span<byte> buffer, List<NamedGroup> list)
        {
            return buffer.WriteVector(ArrayLength_NumBytes, (buf, state) =>
            {
                foreach (var item in list)
                    if (item != NamedGroup.NA)
                        buf = buf.Write(item);

                state.EndLength = buf.Length;
            });
        }
    }
}
